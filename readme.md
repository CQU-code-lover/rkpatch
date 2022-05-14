# 选题

## 名称 

proj128-kernel-livepatch-optimizations

内核热补丁优化

## 要求

### 基础功能

- 内核热补丁间函数冲突检测增强

  - 补丁ko插入时判断其对内核函数的修改是否与当前running的其他补丁冲突，如果冲突，默认情况下报错退出

  - 支持确实要进行冲突覆盖的场景

  - 导出函数冲突信息到sys接口，方便用户态查询读取

- 内核热补丁构建流程优化
  - 热补丁制作过程，大量时间耗费在第一次内核的编译上，可以考虑缓存起内核的二进制编译产物，这样就只需要做第二次增量的内核编译

### 扩展要求

- 内核热补丁一致性模型优化
  - 改进kernel的livepatch所用的consistency model，使其不再是per-task consistency，而是whole system consistency，同时保留其对于kpatch stop_machine方案的性能优势，要求最差性能情况下退化到stop machine的性能。
- 内核热补丁构建流程优化
  - 二进制差异提取工具create-diff-object 性能优化

# 其他内容

见本目录其他文件