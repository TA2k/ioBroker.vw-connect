.class synthetic Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1009
    name = null
.end annotation


# static fields
.field static final synthetic $SwitchMap$io$opentelemetry$api$common$AttributeType:[I

.field static final synthetic $SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/AttributeType;->values()[Lio/opentelemetry/api/common/AttributeType;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    sput-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    sget-object v2, Lio/opentelemetry/api/common/AttributeType;->STRING:Lio/opentelemetry/api/common/AttributeType;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    :catch_0
    const/4 v0, 0x2

    .line 20
    :try_start_1
    sget-object v2, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 21
    .line 22
    sget-object v3, Lio/opentelemetry/api/common/AttributeType;->BOOLEAN:Lio/opentelemetry/api/common/AttributeType;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    aput v0, v2, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 29
    .line 30
    :catch_1
    const/4 v2, 0x3

    .line 31
    :try_start_2
    sget-object v3, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 32
    .line 33
    sget-object v4, Lio/opentelemetry/api/common/AttributeType;->LONG:Lio/opentelemetry/api/common/AttributeType;

    .line 34
    .line 35
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    aput v2, v3, v4
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 40
    .line 41
    :catch_2
    const/4 v3, 0x4

    .line 42
    :try_start_3
    sget-object v4, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 43
    .line 44
    sget-object v5, Lio/opentelemetry/api/common/AttributeType;->DOUBLE:Lio/opentelemetry/api/common/AttributeType;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    aput v3, v4, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 51
    .line 52
    :catch_3
    const/4 v4, 0x5

    .line 53
    :try_start_4
    sget-object v5, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 54
    .line 55
    sget-object v6, Lio/opentelemetry/api/common/AttributeType;->STRING_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 56
    .line 57
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    aput v4, v5, v6
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 62
    .line 63
    :catch_4
    const/4 v5, 0x6

    .line 64
    :try_start_5
    sget-object v6, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 65
    .line 66
    sget-object v7, Lio/opentelemetry/api/common/AttributeType;->BOOLEAN_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 67
    .line 68
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 69
    .line 70
    .line 71
    move-result v7

    .line 72
    aput v5, v6, v7
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 73
    .line 74
    :catch_5
    const/4 v6, 0x7

    .line 75
    :try_start_6
    sget-object v7, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 76
    .line 77
    sget-object v8, Lio/opentelemetry/api/common/AttributeType;->LONG_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 78
    .line 79
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v8

    .line 83
    aput v6, v7, v8
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 84
    .line 85
    :catch_6
    const/16 v7, 0x8

    .line 86
    .line 87
    :try_start_7
    sget-object v8, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    .line 88
    .line 89
    sget-object v9, Lio/opentelemetry/api/common/AttributeType;->DOUBLE_ARRAY:Lio/opentelemetry/api/common/AttributeType;

    .line 90
    .line 91
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    aput v7, v8, v9
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 96
    .line 97
    :catch_7
    invoke-static {}, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->values()[Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    array-length v8, v8

    .line 102
    new-array v8, v8, [I

    .line 103
    .line 104
    sput-object v8, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 105
    .line 106
    :try_start_8
    sget-object v9, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->STRING:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 107
    .line 108
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    aput v1, v8, v9
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 113
    .line 114
    :catch_8
    :try_start_9
    sget-object v1, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 115
    .line 116
    sget-object v8, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->BOOLEAN:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 117
    .line 118
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 119
    .line 120
    .line 121
    move-result v8

    .line 122
    aput v0, v1, v8
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 123
    .line 124
    :catch_9
    :try_start_a
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 125
    .line 126
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->LONG:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 127
    .line 128
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    aput v2, v0, v1
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 133
    .line 134
    :catch_a
    :try_start_b
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 135
    .line 136
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->DOUBLE:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 137
    .line 138
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    aput v3, v0, v1
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 143
    .line 144
    :catch_b
    :try_start_c
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 145
    .line 146
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->STRING_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 147
    .line 148
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    aput v4, v0, v1
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 153
    .line 154
    :catch_c
    :try_start_d
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 155
    .line 156
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->BOOLEAN_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 157
    .line 158
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    aput v5, v0, v1
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 163
    .line 164
    :catch_d
    :try_start_e
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 165
    .line 166
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->LONG_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 167
    .line 168
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    aput v6, v0, v1
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 173
    .line 174
    :catch_e
    :try_start_f
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 175
    .line 176
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->DOUBLE_ARRAY:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 177
    .line 178
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    aput v7, v0, v1
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 183
    .line 184
    :catch_f
    :try_start_10
    sget-object v0, Lio/opentelemetry/api/incubator/internal/InternalExtendedAttributeKeyImpl$1;->$SwitchMap$io$opentelemetry$api$incubator$common$ExtendedAttributeType:[I

    .line 185
    .line 186
    sget-object v1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;->EXTENDED_ATTRIBUTES:Lio/opentelemetry/api/incubator/common/ExtendedAttributeType;

    .line 187
    .line 188
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    const/16 v2, 0x9

    .line 193
    .line 194
    aput v2, v0, v1
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 195
    .line 196
    :catch_10
    return-void
.end method
