# Final LightGBM SHAP Report

## Model Summary

- Model: LightGBM
- Dataset: 5,040 Cowrie sessions
- Features: 30
- Classes: 9

## Global Feature Importance

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | interpreter_command_count | 0.646826 |
| 2 | privilege_command_count | 0.608537 |
| 3 | absolute_path_count | 0.400239 |
| 4 | avg_command_length | 0.306978 |
| 5 | option_count | 0.222879 |
| 6 | file_modify_command_count | 0.185399 |
| 7 | unique_category_count | 0.157716 |
| 8 | event_count | 0.131173 |
| 9 | unique_command_count | 0.129492 |
| 10 | persistence_command_count | 0.122465 |
| 11 | filesystem_command_count | 0.121022 |
| 12 | transfer_command_count | 0.093761 |
| 13 | network_command_count | 0.082665 |
| 14 | std_command_length | 0.078734 |
| 15 | read_command_count | 0.077068 |

## Class-Specific Feature Importance

### benign

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | absolute_path_count | 0.858061 |
| 2 | unique_category_count | 0.819424 |
| 3 | option_count | 0.575728 |
| 4 | unique_command_count | 0.425730 |
| 5 | std_command_length | 0.096341 |
| 6 | unique_transition_count | 0.088665 |
| 7 | event_count | 0.072623 |
| 8 | min_command_length | 0.048806 |
| 9 | duration_ms | 0.032332 |
| 10 | avg_command_length | 0.026003 |
| 11 | system_command_count | 0.020707 |
| 12 | command_diversity | 0.013361 |
| 13 | std_command_gap | 0.012808 |
| 14 | read_command_count | 0.009841 |
| 15 | network_command_count | 0.008069 |

### credential_access

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | absolute_path_count | 0.700232 |
| 2 | interpreter_command_count | 0.671505 |
| 3 | privilege_command_count | 0.374237 |
| 4 | option_count | 0.345585 |
| 5 | file_modify_command_count | 0.274935 |
| 6 | read_command_count | 0.227850 |
| 7 | event_count | 0.222841 |
| 8 | transfer_command_count | 0.200501 |
| 9 | network_command_count | 0.102309 |
| 10 | std_command_length | 0.099222 |
| 11 | avg_command_gap | 0.094775 |
| 12 | avg_command_length | 0.094456 |
| 13 | process_command_count | 0.086760 |
| 14 | std_command_gap | 0.085979 |
| 15 | system_command_count | 0.074771 |

### execution

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | interpreter_command_count | 1.736637 |
| 2 | privilege_command_count | 0.379142 |
| 3 | shell_metacharacter_count | 0.290265 |
| 4 | absolute_path_count | 0.211500 |
| 5 | option_count | 0.167816 |
| 6 | avg_command_length | 0.091094 |
| 7 | std_command_length | 0.065075 |
| 8 | max_command_gap | 0.059334 |
| 9 | std_command_gap | 0.052970 |
| 10 | file_modify_command_count | 0.050347 |
| 11 | avg_command_gap | 0.049632 |
| 12 | command_diversity | 0.049439 |
| 13 | system_command_count | 0.038718 |
| 14 | duration_ms | 0.038259 |
| 15 | event_count | 0.035928 |

### file_discovery

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | filesystem_command_count | 0.751307 |
| 2 | interpreter_command_count | 0.723060 |
| 3 | privilege_command_count | 0.618037 |
| 4 | avg_command_length | 0.427174 |
| 5 | transfer_command_count | 0.204103 |
| 6 | absolute_path_count | 0.157775 |
| 7 | file_modify_command_count | 0.142864 |
| 8 | network_command_count | 0.119943 |
| 9 | persistence_command_count | 0.116640 |
| 10 | identity_command_count | 0.115361 |
| 11 | duration_ms | 0.110880 |
| 12 | read_command_count | 0.088812 |
| 13 | option_count | 0.088690 |
| 14 | std_command_gap | 0.087168 |
| 15 | min_command_length | 0.076945 |

### file_modification

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | file_modify_command_count | 0.956642 |
| 2 | interpreter_command_count | 0.601457 |
| 3 | avg_command_length | 0.571835 |
| 4 | redirection_count | 0.501802 |
| 5 | absolute_path_count | 0.249266 |
| 6 | option_count | 0.149919 |
| 7 | unique_transition_count | 0.143760 |
| 8 | read_command_count | 0.126030 |
| 9 | std_command_length | 0.091047 |
| 10 | transfer_command_count | 0.086658 |
| 11 | duration_ms | 0.078057 |
| 12 | privilege_command_count | 0.075445 |
| 13 | std_command_gap | 0.072953 |
| 14 | max_command_gap | 0.071506 |
| 15 | avg_command_gap | 0.068770 |

### multi_stage

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | privilege_command_count | 0.607626 |
| 2 | unique_command_count | 0.605631 |
| 3 | absolute_path_count | 0.537833 |
| 4 | interpreter_command_count | 0.475122 |
| 5 | unique_category_count | 0.314949 |
| 6 | unique_transition_count | 0.278411 |
| 7 | option_count | 0.173168 |
| 8 | avg_command_length | 0.124635 |
| 9 | std_command_gap | 0.108342 |
| 10 | duration_ms | 0.106146 |
| 11 | process_command_count | 0.095496 |
| 12 | std_command_length | 0.090452 |
| 13 | max_command_gap | 0.089966 |
| 14 | filesystem_command_count | 0.079050 |
| 15 | command_diversity | 0.074660 |

### persistence

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | persistence_command_count | 0.719223 |
| 2 | avg_command_length | 0.710249 |
| 3 | interpreter_command_count | 0.659077 |
| 4 | absolute_path_count | 0.641558 |
| 5 | event_count | 0.609511 |
| 6 | privilege_command_count | 0.560022 |
| 7 | option_count | 0.226140 |
| 8 | network_command_count | 0.155788 |
| 9 | std_command_gap | 0.122599 |
| 10 | avg_command_gap | 0.108055 |
| 11 | duration_ms | 0.091530 |
| 12 | file_modify_command_count | 0.088262 |
| 13 | read_command_count | 0.076378 |
| 14 | std_command_length | 0.064014 |
| 15 | max_command_gap | 0.063310 |

### privilege_activity

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | privilege_command_count | 2.248458 |
| 2 | interpreter_command_count | 0.246134 |
| 3 | avg_command_length | 0.153540 |
| 4 | option_count | 0.142709 |
| 5 | duration_ms | 0.092416 |
| 6 | persistence_command_count | 0.083233 |
| 7 | transfer_command_count | 0.063882 |
| 8 | event_count | 0.054469 |
| 9 | std_command_gap | 0.050671 |
| 10 | min_command_length | 0.036431 |
| 11 | identity_command_count | 0.034353 |
| 12 | std_command_length | 0.033005 |
| 13 | absolute_path_count | 0.032003 |
| 14 | read_command_count | 0.025585 |
| 15 | max_command_gap | 0.024069 |

### reconnaissance

| Rank | Feature | Mean Absolute SHAP |
|---:|---|---:|
| 1 | interpreter_command_count | 0.708438 |
| 2 | privilege_command_count | 0.613868 |
| 3 | avg_command_length | 0.563820 |
| 4 | network_command_count | 0.308046 |
| 5 | transfer_command_count | 0.224655 |
| 6 | absolute_path_count | 0.213924 |
| 7 | option_count | 0.136158 |
| 8 | filesystem_command_count | 0.120139 |
| 9 | unique_category_count | 0.117280 |
| 10 | process_command_count | 0.113131 |
| 11 | file_modify_command_count | 0.107641 |
| 12 | std_command_length | 0.106661 |
| 13 | persistence_command_count | 0.100904 |
| 14 | read_command_count | 0.099738 |
| 15 | avg_command_gap | 0.081284 |

