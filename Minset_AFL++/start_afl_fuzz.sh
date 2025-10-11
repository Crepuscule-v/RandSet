#!/bin/bash

# 配置文件路径
CONFIG_FILE="binaries_config.json"

# 创建新的 tmux 会话
SESSION_NAME="afl_fuzzing_experiment"
tmux new-session -d -s $SESSION_NAME

# 定义 setcover 和 baseline 算法的配置和参数
algorithms=("setcover" "baseline")

# 读取配置文件并遍历每个二进制文件
for binary in $(jq -r 'keys[]' $CONFIG_FILE); do
    # 获取当前二进制文件的配置
    AFL_CFG_PATH=$(jq -r ".\"$binary\".AFL_CFG_PATH" $CONFIG_FILE)
    FUZZ_TARGET=$(jq -r ".\"$binary\".FUZZ_TARGET" $CONFIG_FILE)
    FUZZ_ARGS=$(jq -r ".\"$binary\".FUZZ_ARGS" $CONFIG_FILE)
    INPUT_DIR=$(jq -r ".\"$binary\".INPUT_DIR" $CONFIG_FILE)

    for algo in "${algorithms[@]}"; do
        for round in {1..2}; do
            # 动态构建输出目录，包括算法名称
            OUTPUT_DIR="batch_result_data/$binary/$algo/round_$round"

            # 确保输出目录存在，若不存在则自动创建
            mkdir -p "$OUTPUT_DIR"

            # 根据算法设置 afl-fuzz 的命令参数
            if [ "$algo" == "setcover" ]; then
                FUZZ_MODE="-H"
            else
                FUZZ_MODE="-d"
            fi

            # 创建窗口并运行对应的命令
            if [ $round -eq 1 ]; then
                # 第一个轮次，使用第一个窗口
                tmux send-keys "export AFL_CFG_PATH=$AFL_CFG_PATH" C-m
                tmux send-keys "AFL_NO_UI=1 ./afl-fuzz $FUZZ_MODE -i $INPUT_DIR -o $OUTPUT_DIR $FUZZ_TARGET $FUZZ_ARGS &" C-m
            else
                # 后续轮次，创建新的窗口
                tmux new-window
                tmux send-keys "export AFL_CFG_PATH=$AFL_CFG_PATH" C-m
                tmux send-keys "AFL_NO_UI=1 ./afl-fuzz $FUZZ_MODE -i $INPUT_DIR -o $OUTPUT_DIR $FUZZ_TARGET $FUZZ_ARGS &" C-m
            fi

            # 给窗口命名，便于管理
            tmux rename-window "$binary_$algo_round_$round"
        done
    done
done

# 分离 tmux 会话，任务在后台继续运行
tmux detach

echo "tmux session '$SESSION_NAME' created with all tasks running."
