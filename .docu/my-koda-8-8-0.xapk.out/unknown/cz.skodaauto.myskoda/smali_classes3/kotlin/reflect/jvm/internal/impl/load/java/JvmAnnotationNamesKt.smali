.class public final Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final BUILT_IN_TYPE_QUALIFIER_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final FORCE_FLEXIBILITY_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final JAVAX_CHECK_FOR_NULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_NONNULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_PARAMETERS_ARE_NONNULL_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_PARAMETERS_ARE_NULLABLE_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_TYPE_QUALIFIER_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_TYPE_QUALIFIER_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JAVAX_TYPE_QUALIFIER_NICKNAME_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_NON_NULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_NULLNESS_UNSPECIFIED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_NULL_UNMARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_OLD_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_OLD_NULLNESS_UNSPECIFIED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final JSPECIFY_OLD_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final MUTABLE_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final NOT_NULL_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final NULLABILITY_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final NULLABLE_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final READ_ONLY_ANNOTATIONS:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field

.field private static final UNDER_MIGRATION_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

.field private static final javaToKotlinNameMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 30

    .line 1
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    const-string v0, "org.jspecify.nullness.Nullable"

    .line 4
    .line 5
    invoke-direct {v2, v0}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_OLD_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 9
    .line 10
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 11
    .line 12
    const-string v1, "org.jspecify.nullness.NullMarked"

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_OLD_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 18
    .line 19
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 20
    .line 21
    const-string v3, "org.jspecify.nullness.NullnessUnspecified"

    .line 22
    .line 23
    invoke-direct {v1, v3}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_OLD_NULLNESS_UNSPECIFIED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 27
    .line 28
    new-instance v5, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 29
    .line 30
    const-string v3, "org.jspecify.annotations.NonNull"

    .line 31
    .line 32
    invoke-direct {v5, v3}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v5, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NON_NULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 36
    .line 37
    new-instance v3, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 38
    .line 39
    const-string v4, "org.jspecify.annotations.Nullable"

    .line 40
    .line 41
    invoke-direct {v3, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    sput-object v3, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 45
    .line 46
    new-instance v4, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 47
    .line 48
    const-string v6, "org.jspecify.annotations.NullMarked"

    .line 49
    .line 50
    invoke-direct {v4, v6}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sput-object v4, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 54
    .line 55
    new-instance v6, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 56
    .line 57
    const-string v7, "org.jspecify.annotations.NullnessUnspecified"

    .line 58
    .line 59
    invoke-direct {v6, v7}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    sput-object v6, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULLNESS_UNSPECIFIED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 63
    .line 64
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 65
    .line 66
    const-string v8, "org.jspecify.annotations.NullUnmarked"

    .line 67
    .line 68
    invoke-direct {v7, v8}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    sput-object v7, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULL_UNMARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 72
    .line 73
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 74
    .line 75
    const-string v9, "javax.annotation.meta.TypeQualifier"

    .line 76
    .line 77
    invoke-direct {v8, v9}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    sput-object v8, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 81
    .line 82
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 83
    .line 84
    const-string v9, "javax.annotation.meta.TypeQualifierNickname"

    .line 85
    .line 86
    invoke-direct {v8, v9}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    sput-object v8, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_NICKNAME_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 90
    .line 91
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 92
    .line 93
    const-string v9, "javax.annotation.meta.TypeQualifierDefault"

    .line 94
    .line 95
    invoke-direct {v8, v9}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    sput-object v8, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 99
    .line 100
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 101
    .line 102
    const-string v9, "javax.annotation.Nonnull"

    .line 103
    .line 104
    invoke-direct {v8, v9}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    sput-object v8, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_NONNULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 108
    .line 109
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 110
    .line 111
    const-string v10, "javax.annotation.Nullable"

    .line 112
    .line 113
    invoke-direct {v9, v10}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    sput-object v9, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_NULLABLE_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 117
    .line 118
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 119
    .line 120
    const-string v11, "javax.annotation.CheckForNull"

    .line 121
    .line 122
    invoke-direct {v10, v11}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    sput-object v10, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_CHECK_FOR_NULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 126
    .line 127
    new-instance v11, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 128
    .line 129
    const-string v12, "javax.annotation.ParametersAreNonnullByDefault"

    .line 130
    .line 131
    invoke-direct {v11, v12}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    sput-object v11, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_PARAMETERS_ARE_NONNULL_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 135
    .line 136
    new-instance v11, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 137
    .line 138
    const-string v12, "javax.annotation.ParametersAreNullableByDefault"

    .line 139
    .line 140
    invoke-direct {v11, v12}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    sput-object v11, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_PARAMETERS_ARE_NULLABLE_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 144
    .line 145
    filled-new-array {v8, v10}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 146
    .line 147
    .line 148
    move-result-object v11

    .line 149
    invoke-static {v11}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 150
    .line 151
    .line 152
    move-result-object v11

    .line 153
    sput-object v11, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->BUILT_IN_TYPE_QUALIFIER_ANNOTATIONS:Ljava/util/Set;

    .line 154
    .line 155
    move-object v11, v4

    .line 156
    sget-object v4, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->JETBRAINS_NOT_NULL_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 157
    .line 158
    const-string v12, "JETBRAINS_NOT_NULL_ANNOTATION"

    .line 159
    .line 160
    invoke-static {v4, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    move-object v12, v6

    .line 164
    new-instance v6, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 165
    .line 166
    const-string v13, "android.annotation.NonNull"

    .line 167
    .line 168
    invoke-direct {v6, v13}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    move-object v13, v7

    .line 172
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 173
    .line 174
    const-string v14, "androidx.annotation.NonNull"

    .line 175
    .line 176
    invoke-direct {v7, v14}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    move-object v14, v8

    .line 180
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 181
    .line 182
    const-string v15, "androidx.annotation.RecentlyNonNull"

    .line 183
    .line 184
    invoke-direct {v8, v15}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    move-object v15, v9

    .line 188
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 189
    .line 190
    move-object/from16 v19, v1

    .line 191
    .line 192
    const-string v1, "android.support.annotation.NonNull"

    .line 193
    .line 194
    invoke-direct {v9, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    move-object v1, v10

    .line 198
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 199
    .line 200
    move-object/from16 v16, v1

    .line 201
    .line 202
    const-string v1, "com.android.annotations.NonNull"

    .line 203
    .line 204
    invoke-direct {v10, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    move-object v1, v11

    .line 208
    new-instance v11, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 209
    .line 210
    move-object/from16 v17, v1

    .line 211
    .line 212
    const-string v1, "org.checkerframework.checker.nullness.compatqual.NonNullDecl"

    .line 213
    .line 214
    invoke-direct {v11, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    move-object v1, v12

    .line 218
    new-instance v12, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 219
    .line 220
    move-object/from16 v18, v1

    .line 221
    .line 222
    const-string v1, "org.checkerframework.checker.nullness.qual.NonNull"

    .line 223
    .line 224
    invoke-direct {v12, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    move-object v1, v13

    .line 228
    new-instance v13, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 229
    .line 230
    move-object/from16 v20, v1

    .line 231
    .line 232
    const-string v1, "edu.umd.cs.findbugs.annotations.NonNull"

    .line 233
    .line 234
    invoke-direct {v13, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    move-object v1, v14

    .line 238
    new-instance v14, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 239
    .line 240
    move-object/from16 v21, v1

    .line 241
    .line 242
    const-string v1, "io.reactivex.annotations.NonNull"

    .line 243
    .line 244
    invoke-direct {v14, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    move-object v1, v15

    .line 248
    new-instance v15, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 249
    .line 250
    move-object/from16 v22, v1

    .line 251
    .line 252
    const-string v1, "io.reactivex.rxjava3.annotations.NonNull"

    .line 253
    .line 254
    invoke-direct {v15, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 258
    .line 259
    move-object/from16 v23, v2

    .line 260
    .line 261
    const-string v2, "org.eclipse.jdt.annotation.NonNull"

    .line 262
    .line 263
    invoke-direct {v1, v2}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 267
    .line 268
    move-object/from16 v24, v1

    .line 269
    .line 270
    const-string v1, "lombok.NonNull"

    .line 271
    .line 272
    invoke-direct {v2, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 276
    .line 277
    move-object/from16 v25, v2

    .line 278
    .line 279
    const-string v2, "jakarta.annotation.Nonnull"

    .line 280
    .line 281
    invoke-direct {v1, v2}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    move-object/from16 v2, v18

    .line 285
    .line 286
    move-object/from16 v26, v20

    .line 287
    .line 288
    move-object/from16 v20, v0

    .line 289
    .line 290
    move-object/from16 v18, v1

    .line 291
    .line 292
    move-object/from16 v1, v17

    .line 293
    .line 294
    move-object/from16 v0, v21

    .line 295
    .line 296
    move-object/from16 v17, v25

    .line 297
    .line 298
    move-object/from16 v21, v16

    .line 299
    .line 300
    move-object/from16 v16, v24

    .line 301
    .line 302
    filled-new-array/range {v4 .. v18}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 303
    .line 304
    .line 305
    move-result-object v4

    .line 306
    invoke-static {v4}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 307
    .line 308
    .line 309
    move-result-object v24

    .line 310
    sput-object v24, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->NOT_NULL_ANNOTATIONS:Ljava/util/Set;

    .line 311
    .line 312
    move-object/from16 v17, v1

    .line 313
    .line 314
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->JETBRAINS_NULLABLE_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 315
    .line 316
    const-string v4, "JETBRAINS_NULLABLE_ANNOTATION"

    .line 317
    .line 318
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    new-instance v6, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 322
    .line 323
    const-string v4, "android.annotation.Nullable"

    .line 324
    .line 325
    invoke-direct {v6, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 329
    .line 330
    const-string v4, "androidx.annotation.Nullable"

    .line 331
    .line 332
    invoke-direct {v7, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    new-instance v8, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 336
    .line 337
    const-string v4, "androidx.annotation.RecentlyNullable"

    .line 338
    .line 339
    invoke-direct {v8, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    new-instance v9, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 343
    .line 344
    const-string v4, "android.support.annotation.Nullable"

    .line 345
    .line 346
    invoke-direct {v9, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 350
    .line 351
    const-string v4, "com.android.annotations.Nullable"

    .line 352
    .line 353
    invoke-direct {v10, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    new-instance v11, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 357
    .line 358
    const-string v4, "org.checkerframework.checker.nullness.compatqual.NullableDecl"

    .line 359
    .line 360
    invoke-direct {v11, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    new-instance v12, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 364
    .line 365
    const-string v4, "org.checkerframework.checker.nullness.qual.Nullable"

    .line 366
    .line 367
    invoke-direct {v12, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    new-instance v13, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 371
    .line 372
    const-string v4, "edu.umd.cs.findbugs.annotations.Nullable"

    .line 373
    .line 374
    invoke-direct {v13, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    new-instance v14, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 378
    .line 379
    const-string v4, "edu.umd.cs.findbugs.annotations.PossiblyNull"

    .line 380
    .line 381
    invoke-direct {v14, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    new-instance v15, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 385
    .line 386
    const-string v4, "edu.umd.cs.findbugs.annotations.CheckForNull"

    .line 387
    .line 388
    invoke-direct {v15, v4}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    new-instance v4, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 392
    .line 393
    const-string v5, "io.reactivex.annotations.Nullable"

    .line 394
    .line 395
    invoke-direct {v4, v5}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    new-instance v5, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 399
    .line 400
    move-object/from16 v16, v1

    .line 401
    .line 402
    const-string v1, "io.reactivex.rxjava3.annotations.Nullable"

    .line 403
    .line 404
    invoke-direct {v5, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 405
    .line 406
    .line 407
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 408
    .line 409
    move-object/from16 v18, v2

    .line 410
    .line 411
    const-string v2, "org.eclipse.jdt.annotation.Nullable"

    .line 412
    .line 413
    invoke-direct {v1, v2}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 417
    .line 418
    move-object/from16 v25, v1

    .line 419
    .line 420
    const-string v1, "jakarta.annotation.Nullable"

    .line 421
    .line 422
    invoke-direct {v2, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    move-object/from16 v27, v0

    .line 426
    .line 427
    move-object/from16 v1, v16

    .line 428
    .line 429
    move-object/from16 v28, v17

    .line 430
    .line 431
    move-object/from16 v29, v18

    .line 432
    .line 433
    move-object/from16 v0, v19

    .line 434
    .line 435
    move-object/from16 v18, v25

    .line 436
    .line 437
    move-object/from16 v19, v2

    .line 438
    .line 439
    move-object/from16 v16, v4

    .line 440
    .line 441
    move-object/from16 v17, v5

    .line 442
    .line 443
    move-object/from16 v5, v21

    .line 444
    .line 445
    move-object/from16 v4, v22

    .line 446
    .line 447
    move-object/from16 v2, v23

    .line 448
    .line 449
    filled-new-array/range {v1 .. v19}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 450
    .line 451
    .line 452
    move-result-object v1

    .line 453
    invoke-static {v1}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->NULLABLE_ANNOTATIONS:Ljava/util/Set;

    .line 458
    .line 459
    move-object/from16 v2, v29

    .line 460
    .line 461
    filled-new-array {v0, v2}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 466
    .line 467
    .line 468
    move-result-object v0

    .line 469
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->FORCE_FLEXIBILITY_ANNOTATIONS:Ljava/util/Set;

    .line 470
    .line 471
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 472
    .line 473
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 474
    .line 475
    .line 476
    move-object/from16 v2, v24

    .line 477
    .line 478
    check-cast v2, Ljava/lang/Iterable;

    .line 479
    .line 480
    invoke-static {v0, v2}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    check-cast v1, Ljava/lang/Iterable;

    .line 485
    .line 486
    invoke-static {v0, v1}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    move-object/from16 v1, v27

    .line 491
    .line 492
    invoke-static {v0, v1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    move-object/from16 v1, v20

    .line 497
    .line 498
    invoke-static {v0, v1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    move-object/from16 v1, v28

    .line 503
    .line 504
    invoke-static {v0, v1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    move-object/from16 v1, v26

    .line 509
    .line 510
    invoke-static {v0, v1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 511
    .line 512
    .line 513
    move-result-object v0

    .line 514
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->NULLABILITY_ANNOTATIONS:Ljava/util/Set;

    .line 515
    .line 516
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->JETBRAINS_READONLY_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 517
    .line 518
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->READONLY_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 519
    .line 520
    filled-new-array {v0, v1}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 521
    .line 522
    .line 523
    move-result-object v0

    .line 524
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 525
    .line 526
    .line 527
    move-result-object v0

    .line 528
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->READ_ONLY_ANNOTATIONS:Ljava/util/Set;

    .line 529
    .line 530
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->JETBRAINS_MUTABLE_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 531
    .line 532
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->MUTABLE_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 533
    .line 534
    filled-new-array {v0, v1}, [Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 535
    .line 536
    .line 537
    move-result-object v0

    .line 538
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 539
    .line 540
    .line 541
    move-result-object v0

    .line 542
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->MUTABLE_ANNOTATIONS:Ljava/util/Set;

    .line 543
    .line 544
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->TARGET_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 545
    .line 546
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/builtins/StandardNames$FqNames;->target:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 547
    .line 548
    new-instance v2, Llx0/l;

    .line 549
    .line 550
    invoke-direct {v2, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 551
    .line 552
    .line 553
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->RETENTION_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 554
    .line 555
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/builtins/StandardNames$FqNames;->retention:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 556
    .line 557
    new-instance v3, Llx0/l;

    .line 558
    .line 559
    invoke-direct {v3, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 560
    .line 561
    .line 562
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->DEPRECATED_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 563
    .line 564
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/builtins/StandardNames$FqNames;->deprecated:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 565
    .line 566
    new-instance v4, Llx0/l;

    .line 567
    .line 568
    invoke-direct {v4, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 569
    .line 570
    .line 571
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNames;->DOCUMENTED_ANNOTATION:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 572
    .line 573
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/builtins/StandardNames$FqNames;->mustBeDocumented:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 574
    .line 575
    new-instance v5, Llx0/l;

    .line 576
    .line 577
    invoke-direct {v5, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 578
    .line 579
    .line 580
    filled-new-array {v2, v3, v4, v5}, [Llx0/l;

    .line 581
    .line 582
    .line 583
    move-result-object v0

    .line 584
    invoke-static {v0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 585
    .line 586
    .line 587
    move-result-object v0

    .line 588
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->javaToKotlinNameMap:Ljava/util/Map;

    .line 589
    .line 590
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 591
    .line 592
    const-string v1, "kotlin.annotations.jvm.UnderMigration"

    .line 593
    .line 594
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/name/FqName;-><init>(Ljava/lang/String;)V

    .line 595
    .line 596
    .line 597
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->UNDER_MIGRATION_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 598
    .line 599
    return-void
.end method

.method public static final getBUILT_IN_TYPE_QUALIFIER_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->BUILT_IN_TYPE_QUALIFIER_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getFORCE_FLEXIBILITY_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->FORCE_FLEXIBILITY_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_NONNULL_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_NONNULL_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_PARAMETERS_ARE_NONNULL_BY_DEFAULT_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_PARAMETERS_ARE_NONNULL_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_PARAMETERS_ARE_NULLABLE_BY_DEFAULT_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_PARAMETERS_ARE_NULLABLE_BY_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_TYPE_QUALIFIER_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_TYPE_QUALIFIER_DEFAULT_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_DEFAULT_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJAVAX_TYPE_QUALIFIER_NICKNAME_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JAVAX_TYPE_QUALIFIER_NICKNAME_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJSPECIFY_NULL_MARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJSPECIFY_NULL_UNMARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_NULL_UNMARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getJSPECIFY_OLD_NULL_MARKED_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->JSPECIFY_OLD_NULL_MARKED_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getMUTABLE_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->MUTABLE_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getNOT_NULL_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->NOT_NULL_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getNULLABLE_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->NULLABLE_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getREAD_ONLY_ANNOTATIONS()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->READ_ONLY_ANNOTATIONS:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final getUNDER_MIGRATION_ANNOTATION_FQ_NAME()Lkotlin/reflect/jvm/internal/impl/name/FqName;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/JvmAnnotationNamesKt;->UNDER_MIGRATION_ANNOTATION_FQ_NAME:Lkotlin/reflect/jvm/internal/impl/name/FqName;

    .line 2
    .line 3
    return-object v0
.end method
