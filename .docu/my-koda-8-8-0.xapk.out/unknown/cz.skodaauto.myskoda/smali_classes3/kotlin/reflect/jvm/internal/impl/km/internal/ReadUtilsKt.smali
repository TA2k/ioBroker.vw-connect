.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt$WhenMappings;
    }
.end annotation


# direct methods
.method public static final getClassName(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;I)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;->getQualifiedClassName(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;->isLocalClassName(I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    const-string p0, "."

    .line 17
    .line 18
    invoke-static {p0, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    return-object v0
.end method

.method public static final readAnnotation(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;)Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strings"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;->getId()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-static {p1, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->getClassName(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;I)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;->getArgumentList()Ljava/util/List;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v1, "getArgumentList(...)"

    .line 24
    .line 25
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p0, Ljava/lang/Iterable;

    .line 29
    .line 30
    new-instance v1, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument;

    .line 50
    .line 51
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument;->getValue()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    const-string v4, "getValue(...)"

    .line 56
    .line 57
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v3, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->readAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;)Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    if-eqz v3, :cond_1

    .line 65
    .line 66
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument;->getNameId()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-interface {p1, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;->getString(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    new-instance v4, Llx0/l;

    .line 75
    .line 76
    invoke-direct {v4, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_1
    const/4 v4, 0x0

    .line 81
    :goto_1
    if-eqz v4, :cond_0

    .line 82
    .line 83
    invoke-interface {v1, v4}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_2
    invoke-static {v1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;

    .line 92
    .line 93
    invoke-direct {p1, v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 94
    .line 95
    .line 96
    return-object p1
.end method

.method public static final readAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;)Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strings"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->IS_UNSIGNED:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 12
    .line 13
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getFlags()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->get(I)Ljava/lang/Boolean;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, 0x1

    .line 26
    const/4 v2, -0x1

    .line 27
    const/4 v3, 0x0

    .line 28
    if-eqz v0, :cond_5

    .line 29
    .line 30
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getType()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    if-nez p1, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    aget v2, v0, p1

    .line 44
    .line 45
    :goto_0
    if-eq v2, v1, :cond_4

    .line 46
    .line 47
    const/4 p1, 0x2

    .line 48
    if-eq v2, p1, :cond_3

    .line 49
    .line 50
    const/4 p1, 0x3

    .line 51
    if-eq v2, p1, :cond_2

    .line 52
    .line 53
    const/4 p1, 0x4

    .line 54
    if-ne v2, p1, :cond_1

    .line 55
    .line 56
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;

    .line 57
    .line 58
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 59
    .line 60
    .line 61
    move-result-wide v0

    .line 62
    invoke-direct {p1, v0, v1, v3}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;-><init>(JLkotlin/jvm/internal/g;)V

    .line 63
    .line 64
    .line 65
    return-object p1

    .line 66
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    new-instance v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v1, "Cannot read value of unsigned type: "

    .line 71
    .line 72
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getType()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p1

    .line 94
    :cond_2
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UIntValue;

    .line 95
    .line 96
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v0

    .line 100
    long-to-int p0, v0

    .line 101
    invoke-direct {p1, p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UIntValue;-><init>(ILkotlin/jvm/internal/g;)V

    .line 102
    .line 103
    .line 104
    return-object p1

    .line 105
    :cond_3
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;

    .line 106
    .line 107
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 108
    .line 109
    .line 110
    move-result-wide v0

    .line 111
    long-to-int p0, v0

    .line 112
    int-to-short p0, p0

    .line 113
    invoke-direct {p1, p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;-><init>(SLkotlin/jvm/internal/g;)V

    .line 114
    .line 115
    .line 116
    return-object p1

    .line 117
    :cond_4
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UByteValue;

    .line 118
    .line 119
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 120
    .line 121
    .line 122
    move-result-wide v0

    .line 123
    long-to-int p0, v0

    .line 124
    int-to-byte p0, p0

    .line 125
    invoke-direct {p1, p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UByteValue;-><init>(BLkotlin/jvm/internal/g;)V

    .line 126
    .line 127
    .line 128
    return-object p1

    .line 129
    :cond_5
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getType()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Type;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    if-nez v0, :cond_6

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_6
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    aget v2, v2, v0

    .line 143
    .line 144
    :goto_1
    packed-switch v2, :pswitch_data_0

    .line 145
    .line 146
    .line 147
    :pswitch_0
    new-instance p0, La8/r0;

    .line 148
    .line 149
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 150
    .line 151
    .line 152
    throw p0

    .line 153
    :pswitch_1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getArrayElementList()Ljava/util/List;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    const-string v0, "getArrayElementList(...)"

    .line 158
    .line 159
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    check-cast p0, Ljava/lang/Iterable;

    .line 163
    .line 164
    new-instance v0, Ljava/util/ArrayList;

    .line 165
    .line 166
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 167
    .line 168
    .line 169
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    :cond_7
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    if-eqz v1, :cond_8

    .line 178
    .line 179
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;

    .line 184
    .line 185
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    invoke-static {v1, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->readAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;)Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    if-eqz v1, :cond_7

    .line 193
    .line 194
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_8
    new-instance p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayValue;

    .line 199
    .line 200
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayValue;-><init>(Ljava/util/List;)V

    .line 201
    .line 202
    .line 203
    return-object p0

    .line 204
    :pswitch_2
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$AnnotationValue;

    .line 205
    .line 206
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getAnnotation()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    const-string v1, "getAnnotation(...)"

    .line 211
    .line 212
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->readAnnotation(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;)Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$AnnotationValue;-><init>(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;)V

    .line 220
    .line 221
    .line 222
    return-object v0

    .line 223
    :pswitch_3
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;

    .line 224
    .line 225
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getClassId()I

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    invoke-static {p1, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->getClassName(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;I)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getEnumValueId()I

    .line 234
    .line 235
    .line 236
    move-result p0

    .line 237
    invoke-interface {p1, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;->getString(I)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    invoke-direct {v0, v1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$EnumValue;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    return-object v0

    .line 245
    :pswitch_4
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getClassId()I

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    invoke-static {p1, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/ReadUtilsKt;->getClassName(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;I)Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getArrayDimensionCount()I

    .line 254
    .line 255
    .line 256
    move-result v0

    .line 257
    if-nez v0, :cond_9

    .line 258
    .line 259
    new-instance p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$KClassValue;

    .line 260
    .line 261
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$KClassValue;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    return-object p0

    .line 265
    :cond_9
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;

    .line 266
    .line 267
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getArrayDimensionCount()I

    .line 268
    .line 269
    .line 270
    move-result p0

    .line 271
    invoke-direct {v0, p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ArrayKClassValue;-><init>(Ljava/lang/String;I)V

    .line 272
    .line 273
    .line 274
    return-object v0

    .line 275
    :pswitch_5
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$StringValue;

    .line 276
    .line 277
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getStringValue()I

    .line 278
    .line 279
    .line 280
    move-result p0

    .line 281
    invoke-interface {p1, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;->getString(I)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    invoke-direct {v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$StringValue;-><init>(Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    return-object v0

    .line 289
    :pswitch_6
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$BooleanValue;

    .line 290
    .line 291
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 292
    .line 293
    .line 294
    move-result-wide v2

    .line 295
    const-wide/16 v4, 0x0

    .line 296
    .line 297
    cmp-long p0, v2, v4

    .line 298
    .line 299
    if-eqz p0, :cond_a

    .line 300
    .line 301
    goto :goto_3

    .line 302
    :cond_a
    const/4 v1, 0x0

    .line 303
    :goto_3
    invoke-direct {p1, v1}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$BooleanValue;-><init>(Z)V

    .line 304
    .line 305
    .line 306
    return-object p1

    .line 307
    :pswitch_7
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$DoubleValue;

    .line 308
    .line 309
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getDoubleValue()D

    .line 310
    .line 311
    .line 312
    move-result-wide v0

    .line 313
    invoke-direct {p1, v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$DoubleValue;-><init>(D)V

    .line 314
    .line 315
    .line 316
    return-object p1

    .line 317
    :pswitch_8
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$FloatValue;

    .line 318
    .line 319
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getFloatValue()F

    .line 320
    .line 321
    .line 322
    move-result p0

    .line 323
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$FloatValue;-><init>(F)V

    .line 324
    .line 325
    .line 326
    return-object p1

    .line 327
    :pswitch_9
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$CharValue;

    .line 328
    .line 329
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 330
    .line 331
    .line 332
    move-result-wide v0

    .line 333
    long-to-int p0, v0

    .line 334
    int-to-char p0, p0

    .line 335
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$CharValue;-><init>(C)V

    .line 336
    .line 337
    .line 338
    return-object p1

    .line 339
    :pswitch_a
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;

    .line 340
    .line 341
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 342
    .line 343
    .line 344
    move-result-wide v0

    .line 345
    invoke-direct {p1, v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;-><init>(J)V

    .line 346
    .line 347
    .line 348
    return-object p1

    .line 349
    :pswitch_b
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$IntValue;

    .line 350
    .line 351
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 352
    .line 353
    .line 354
    move-result-wide v0

    .line 355
    long-to-int p0, v0

    .line 356
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$IntValue;-><init>(I)V

    .line 357
    .line 358
    .line 359
    return-object p1

    .line 360
    :pswitch_c
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ShortValue;

    .line 361
    .line 362
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 363
    .line 364
    .line 365
    move-result-wide v0

    .line 366
    long-to-int p0, v0

    .line 367
    int-to-short p0, p0

    .line 368
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ShortValue;-><init>(S)V

    .line 369
    .line 370
    .line 371
    return-object p1

    .line 372
    :pswitch_d
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ByteValue;

    .line 373
    .line 374
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;->getIntValue()J

    .line 375
    .line 376
    .line 377
    move-result-wide v0

    .line 378
    long-to-int p0, v0

    .line 379
    int-to-byte p0, p0

    .line 380
    invoke-direct {p1, p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ByteValue;-><init>(B)V

    .line 381
    .line 382
    .line 383
    return-object p1

    .line 384
    :pswitch_e
    return-object v3

    .line 385
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_e
        :pswitch_0
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
