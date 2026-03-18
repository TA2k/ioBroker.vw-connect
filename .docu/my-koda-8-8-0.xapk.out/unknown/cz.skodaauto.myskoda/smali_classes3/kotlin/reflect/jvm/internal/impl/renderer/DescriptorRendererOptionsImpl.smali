.class public final Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;


# static fields
.field static final synthetic $$delegatedProperties:[Lhy0/z;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Lhy0/z;"
        }
    .end annotation
.end field


# instance fields
.field private final actualPropertiesInPrimaryConstructor$delegate:Ldy0/c;

.field private final alwaysRenderModifiers$delegate:Ldy0/c;

.field private final annotationArgumentsRenderingPolicy$delegate:Ldy0/c;

.field private final annotationFilter$delegate:Ldy0/c;

.field private final boldOnlyForNamesInHtml$delegate:Ldy0/c;

.field private final classWithPrimaryConstructor$delegate:Ldy0/c;

.field private final classifierNamePolicy$delegate:Ldy0/c;

.field private final debugMode$delegate:Ldy0/c;

.field private final defaultParameterValueRenderer$delegate:Ldy0/c;

.field private final eachAnnotationOnNewLine$delegate:Ldy0/c;

.field private final enhancedTypes$delegate:Ldy0/c;

.field private final excludedAnnotationClasses$delegate:Ldy0/c;

.field private final excludedTypeAnnotationClasses$delegate:Ldy0/c;

.field private final includeAdditionalModifiers$delegate:Ldy0/c;

.field private final includePropertyConstant$delegate:Ldy0/c;

.field private final informativeErrorType$delegate:Ldy0/c;

.field private isLocked:Z

.field private final modifiers$delegate:Ldy0/c;

.field private final normalizedVisibilities$delegate:Ldy0/c;

.field private final overrideRenderingPolicy$delegate:Ldy0/c;

.field private final parameterNameRenderingPolicy$delegate:Ldy0/c;

.field private final parameterNamesInFunctionalTypes$delegate:Ldy0/c;

.field private final presentableUnresolvedTypes$delegate:Ldy0/c;

.field private final propertyAccessorRenderingPolicy$delegate:Ldy0/c;

.field private final propertyConstantRenderer$delegate:Ldy0/c;

.field private final receiverAfterName$delegate:Ldy0/c;

.field private final renderAbbreviatedTypeComments$delegate:Ldy0/c;

.field private final renderCompanionObjectName$delegate:Ldy0/c;

.field private final renderConstructorDelegation$delegate:Ldy0/c;

.field private final renderConstructorKeyword$delegate:Ldy0/c;

.field private final renderDefaultAnnotationArguments$delegate:Ldy0/c;

.field private final renderDefaultModality$delegate:Ldy0/c;

.field private final renderDefaultVisibility$delegate:Ldy0/c;

.field private final renderFunctionContracts$delegate:Ldy0/c;

.field private final renderPrimaryConstructorParametersAsProperties$delegate:Ldy0/c;

.field private final renderTypeExpansions$delegate:Ldy0/c;

.field private final renderUnabbreviatedType$delegate:Ldy0/c;

.field private final secondaryConstructorsAsPrimary$delegate:Ldy0/c;

.field private final startFromDeclarationKeyword$delegate:Ldy0/c;

.field private final startFromName$delegate:Ldy0/c;

.field private final textFormat$delegate:Ldy0/c;

.field private final typeNormalizer$delegate:Ldy0/c;

.field private final uninferredTypeParameterAsName$delegate:Ldy0/c;

.field private final unitReturnType$delegate:Ldy0/c;

.field private final valueParametersHandler$delegate:Ldy0/c;

.field private final verbose$delegate:Ldy0/c;

.field private final withDefinedIn$delegate:Ldy0/c;

.field private final withSourceFileForTopLevel$delegate:Ldy0/c;

.field private final withoutReturnType$delegate:Ldy0/c;

.field private final withoutSuperTypes$delegate:Ldy0/c;

.field private final withoutTypeParameters$delegate:Ldy0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 54

    .line 1
    new-instance v0, Lkotlin/jvm/internal/r;

    .line 2
    .line 3
    const-class v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;

    .line 4
    .line 5
    const-string v2, "classifierNamePolicy"

    .line 6
    .line 7
    const-string v3, "getClassifierNamePolicy()Lorg/jetbrains/kotlin/renderer/ClassifierNamePolicy;"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v1, v2, v3, v4}, Lkotlin/jvm/internal/r;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v3, "withDefinedIn"

    .line 20
    .line 21
    const-string v5, "getWithDefinedIn()Z"

    .line 22
    .line 23
    invoke-static {v1, v3, v5, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const-string v5, "withSourceFileForTopLevel"

    .line 28
    .line 29
    const-string v6, "getWithSourceFileForTopLevel()Z"

    .line 30
    .line 31
    invoke-static {v1, v5, v6, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    const-string v6, "modifiers"

    .line 36
    .line 37
    const-string v7, "getModifiers()Ljava/util/Set;"

    .line 38
    .line 39
    invoke-static {v1, v6, v7, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    const-string v7, "startFromName"

    .line 44
    .line 45
    const-string v8, "getStartFromName()Z"

    .line 46
    .line 47
    invoke-static {v1, v7, v8, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    const-string v8, "startFromDeclarationKeyword"

    .line 52
    .line 53
    const-string v9, "getStartFromDeclarationKeyword()Z"

    .line 54
    .line 55
    invoke-static {v1, v8, v9, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    const-string v9, "debugMode"

    .line 60
    .line 61
    const-string v10, "getDebugMode()Z"

    .line 62
    .line 63
    invoke-static {v1, v9, v10, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    const-string v10, "classWithPrimaryConstructor"

    .line 68
    .line 69
    const-string v11, "getClassWithPrimaryConstructor()Z"

    .line 70
    .line 71
    invoke-static {v1, v10, v11, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    const-string v11, "verbose"

    .line 76
    .line 77
    const-string v12, "getVerbose()Z"

    .line 78
    .line 79
    invoke-static {v1, v11, v12, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 80
    .line 81
    .line 82
    move-result-object v11

    .line 83
    const-string v12, "unitReturnType"

    .line 84
    .line 85
    const-string v13, "getUnitReturnType()Z"

    .line 86
    .line 87
    invoke-static {v1, v12, v13, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 88
    .line 89
    .line 90
    move-result-object v12

    .line 91
    const-string v13, "withoutReturnType"

    .line 92
    .line 93
    const-string v14, "getWithoutReturnType()Z"

    .line 94
    .line 95
    invoke-static {v1, v13, v14, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 96
    .line 97
    .line 98
    move-result-object v13

    .line 99
    const-string v14, "enhancedTypes"

    .line 100
    .line 101
    const-string v15, "getEnhancedTypes()Z"

    .line 102
    .line 103
    invoke-static {v1, v14, v15, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 104
    .line 105
    .line 106
    move-result-object v14

    .line 107
    const-string v15, "normalizedVisibilities"

    .line 108
    .line 109
    move-object/from16 v16, v0

    .line 110
    .line 111
    const-string v0, "getNormalizedVisibilities()Z"

    .line 112
    .line 113
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    const-string v15, "renderDefaultVisibility"

    .line 118
    .line 119
    move-object/from16 v17, v0

    .line 120
    .line 121
    const-string v0, "getRenderDefaultVisibility()Z"

    .line 122
    .line 123
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    const-string v15, "renderDefaultModality"

    .line 128
    .line 129
    move-object/from16 v18, v0

    .line 130
    .line 131
    const-string v0, "getRenderDefaultModality()Z"

    .line 132
    .line 133
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    const-string v15, "renderConstructorDelegation"

    .line 138
    .line 139
    move-object/from16 v19, v0

    .line 140
    .line 141
    const-string v0, "getRenderConstructorDelegation()Z"

    .line 142
    .line 143
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    const-string v15, "renderPrimaryConstructorParametersAsProperties"

    .line 148
    .line 149
    move-object/from16 v20, v0

    .line 150
    .line 151
    const-string v0, "getRenderPrimaryConstructorParametersAsProperties()Z"

    .line 152
    .line 153
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    const-string v15, "actualPropertiesInPrimaryConstructor"

    .line 158
    .line 159
    move-object/from16 v21, v0

    .line 160
    .line 161
    const-string v0, "getActualPropertiesInPrimaryConstructor()Z"

    .line 162
    .line 163
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    const-string v15, "uninferredTypeParameterAsName"

    .line 168
    .line 169
    move-object/from16 v22, v0

    .line 170
    .line 171
    const-string v0, "getUninferredTypeParameterAsName()Z"

    .line 172
    .line 173
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    const-string v15, "includePropertyConstant"

    .line 178
    .line 179
    move-object/from16 v23, v0

    .line 180
    .line 181
    const-string v0, "getIncludePropertyConstant()Z"

    .line 182
    .line 183
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    const-string v15, "propertyConstantRenderer"

    .line 188
    .line 189
    move-object/from16 v24, v0

    .line 190
    .line 191
    const-string v0, "getPropertyConstantRenderer()Lkotlin/jvm/functions/Function1;"

    .line 192
    .line 193
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    const-string v15, "withoutTypeParameters"

    .line 198
    .line 199
    move-object/from16 v25, v0

    .line 200
    .line 201
    const-string v0, "getWithoutTypeParameters()Z"

    .line 202
    .line 203
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    const-string v15, "withoutSuperTypes"

    .line 208
    .line 209
    move-object/from16 v26, v0

    .line 210
    .line 211
    const-string v0, "getWithoutSuperTypes()Z"

    .line 212
    .line 213
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    const-string v15, "typeNormalizer"

    .line 218
    .line 219
    move-object/from16 v27, v0

    .line 220
    .line 221
    const-string v0, "getTypeNormalizer()Lkotlin/jvm/functions/Function1;"

    .line 222
    .line 223
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    const-string v15, "defaultParameterValueRenderer"

    .line 228
    .line 229
    move-object/from16 v28, v0

    .line 230
    .line 231
    const-string v0, "getDefaultParameterValueRenderer()Lkotlin/jvm/functions/Function1;"

    .line 232
    .line 233
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    const-string v15, "secondaryConstructorsAsPrimary"

    .line 238
    .line 239
    move-object/from16 v29, v0

    .line 240
    .line 241
    const-string v0, "getSecondaryConstructorsAsPrimary()Z"

    .line 242
    .line 243
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    const-string v15, "overrideRenderingPolicy"

    .line 248
    .line 249
    move-object/from16 v30, v0

    .line 250
    .line 251
    const-string v0, "getOverrideRenderingPolicy()Lorg/jetbrains/kotlin/renderer/OverrideRenderingPolicy;"

    .line 252
    .line 253
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    const-string v15, "valueParametersHandler"

    .line 258
    .line 259
    move-object/from16 v31, v0

    .line 260
    .line 261
    const-string v0, "getValueParametersHandler()Lorg/jetbrains/kotlin/renderer/DescriptorRenderer$ValueParametersHandler;"

    .line 262
    .line 263
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    const-string v15, "textFormat"

    .line 268
    .line 269
    move-object/from16 v32, v0

    .line 270
    .line 271
    const-string v0, "getTextFormat()Lorg/jetbrains/kotlin/renderer/RenderingFormat;"

    .line 272
    .line 273
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    const-string v15, "parameterNameRenderingPolicy"

    .line 278
    .line 279
    move-object/from16 v33, v0

    .line 280
    .line 281
    const-string v0, "getParameterNameRenderingPolicy()Lorg/jetbrains/kotlin/renderer/ParameterNameRenderingPolicy;"

    .line 282
    .line 283
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    const-string v15, "receiverAfterName"

    .line 288
    .line 289
    move-object/from16 v34, v0

    .line 290
    .line 291
    const-string v0, "getReceiverAfterName()Z"

    .line 292
    .line 293
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    const-string v15, "renderCompanionObjectName"

    .line 298
    .line 299
    move-object/from16 v35, v0

    .line 300
    .line 301
    const-string v0, "getRenderCompanionObjectName()Z"

    .line 302
    .line 303
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    const-string v15, "propertyAccessorRenderingPolicy"

    .line 308
    .line 309
    move-object/from16 v36, v0

    .line 310
    .line 311
    const-string v0, "getPropertyAccessorRenderingPolicy()Lorg/jetbrains/kotlin/renderer/PropertyAccessorRenderingPolicy;"

    .line 312
    .line 313
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    const-string v15, "renderDefaultAnnotationArguments"

    .line 318
    .line 319
    move-object/from16 v37, v0

    .line 320
    .line 321
    const-string v0, "getRenderDefaultAnnotationArguments()Z"

    .line 322
    .line 323
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    const-string v15, "eachAnnotationOnNewLine"

    .line 328
    .line 329
    move-object/from16 v38, v0

    .line 330
    .line 331
    const-string v0, "getEachAnnotationOnNewLine()Z"

    .line 332
    .line 333
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    const-string v15, "excludedAnnotationClasses"

    .line 338
    .line 339
    move-object/from16 v39, v0

    .line 340
    .line 341
    const-string v0, "getExcludedAnnotationClasses()Ljava/util/Set;"

    .line 342
    .line 343
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 344
    .line 345
    .line 346
    move-result-object v0

    .line 347
    const-string v15, "excludedTypeAnnotationClasses"

    .line 348
    .line 349
    move-object/from16 v40, v0

    .line 350
    .line 351
    const-string v0, "getExcludedTypeAnnotationClasses()Ljava/util/Set;"

    .line 352
    .line 353
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    const-string v15, "annotationFilter"

    .line 358
    .line 359
    move-object/from16 v41, v0

    .line 360
    .line 361
    const-string v0, "getAnnotationFilter()Lkotlin/jvm/functions/Function1;"

    .line 362
    .line 363
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    const-string v15, "annotationArgumentsRenderingPolicy"

    .line 368
    .line 369
    move-object/from16 v42, v0

    .line 370
    .line 371
    const-string v0, "getAnnotationArgumentsRenderingPolicy()Lorg/jetbrains/kotlin/renderer/AnnotationArgumentsRenderingPolicy;"

    .line 372
    .line 373
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    const-string v15, "alwaysRenderModifiers"

    .line 378
    .line 379
    move-object/from16 v43, v0

    .line 380
    .line 381
    const-string v0, "getAlwaysRenderModifiers()Z"

    .line 382
    .line 383
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 384
    .line 385
    .line 386
    move-result-object v0

    .line 387
    const-string v15, "renderConstructorKeyword"

    .line 388
    .line 389
    move-object/from16 v44, v0

    .line 390
    .line 391
    const-string v0, "getRenderConstructorKeyword()Z"

    .line 392
    .line 393
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    const-string v15, "renderUnabbreviatedType"

    .line 398
    .line 399
    move-object/from16 v45, v0

    .line 400
    .line 401
    const-string v0, "getRenderUnabbreviatedType()Z"

    .line 402
    .line 403
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 404
    .line 405
    .line 406
    move-result-object v0

    .line 407
    const-string v15, "renderTypeExpansions"

    .line 408
    .line 409
    move-object/from16 v46, v0

    .line 410
    .line 411
    const-string v0, "getRenderTypeExpansions()Z"

    .line 412
    .line 413
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    const-string v15, "renderAbbreviatedTypeComments"

    .line 418
    .line 419
    move-object/from16 v47, v0

    .line 420
    .line 421
    const-string v0, "getRenderAbbreviatedTypeComments()Z"

    .line 422
    .line 423
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    const-string v15, "includeAdditionalModifiers"

    .line 428
    .line 429
    move-object/from16 v48, v0

    .line 430
    .line 431
    const-string v0, "getIncludeAdditionalModifiers()Z"

    .line 432
    .line 433
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 434
    .line 435
    .line 436
    move-result-object v0

    .line 437
    const-string v15, "parameterNamesInFunctionalTypes"

    .line 438
    .line 439
    move-object/from16 v49, v0

    .line 440
    .line 441
    const-string v0, "getParameterNamesInFunctionalTypes()Z"

    .line 442
    .line 443
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 444
    .line 445
    .line 446
    move-result-object v0

    .line 447
    const-string v15, "renderFunctionContracts"

    .line 448
    .line 449
    move-object/from16 v50, v0

    .line 450
    .line 451
    const-string v0, "getRenderFunctionContracts()Z"

    .line 452
    .line 453
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    const-string v15, "presentableUnresolvedTypes"

    .line 458
    .line 459
    move-object/from16 v51, v0

    .line 460
    .line 461
    const-string v0, "getPresentableUnresolvedTypes()Z"

    .line 462
    .line 463
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 464
    .line 465
    .line 466
    move-result-object v0

    .line 467
    const-string v15, "boldOnlyForNamesInHtml"

    .line 468
    .line 469
    move-object/from16 v52, v0

    .line 470
    .line 471
    const-string v0, "getBoldOnlyForNamesInHtml()Z"

    .line 472
    .line 473
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    const-string v15, "informativeErrorType"

    .line 478
    .line 479
    move-object/from16 v53, v0

    .line 480
    .line 481
    const-string v0, "getInformativeErrorType()Z"

    .line 482
    .line 483
    invoke-static {v1, v15, v0, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    const/16 v1, 0x32

    .line 488
    .line 489
    new-array v1, v1, [Lhy0/z;

    .line 490
    .line 491
    aput-object v16, v1, v4

    .line 492
    .line 493
    const/4 v2, 0x1

    .line 494
    aput-object v3, v1, v2

    .line 495
    .line 496
    const/4 v2, 0x2

    .line 497
    aput-object v5, v1, v2

    .line 498
    .line 499
    const/4 v2, 0x3

    .line 500
    aput-object v6, v1, v2

    .line 501
    .line 502
    const/4 v2, 0x4

    .line 503
    aput-object v7, v1, v2

    .line 504
    .line 505
    const/4 v2, 0x5

    .line 506
    aput-object v8, v1, v2

    .line 507
    .line 508
    const/4 v2, 0x6

    .line 509
    aput-object v9, v1, v2

    .line 510
    .line 511
    const/4 v2, 0x7

    .line 512
    aput-object v10, v1, v2

    .line 513
    .line 514
    const/16 v2, 0x8

    .line 515
    .line 516
    aput-object v11, v1, v2

    .line 517
    .line 518
    const/16 v2, 0x9

    .line 519
    .line 520
    aput-object v12, v1, v2

    .line 521
    .line 522
    const/16 v2, 0xa

    .line 523
    .line 524
    aput-object v13, v1, v2

    .line 525
    .line 526
    const/16 v2, 0xb

    .line 527
    .line 528
    aput-object v14, v1, v2

    .line 529
    .line 530
    const/16 v2, 0xc

    .line 531
    .line 532
    aput-object v17, v1, v2

    .line 533
    .line 534
    const/16 v2, 0xd

    .line 535
    .line 536
    aput-object v18, v1, v2

    .line 537
    .line 538
    const/16 v2, 0xe

    .line 539
    .line 540
    aput-object v19, v1, v2

    .line 541
    .line 542
    const/16 v2, 0xf

    .line 543
    .line 544
    aput-object v20, v1, v2

    .line 545
    .line 546
    const/16 v2, 0x10

    .line 547
    .line 548
    aput-object v21, v1, v2

    .line 549
    .line 550
    const/16 v2, 0x11

    .line 551
    .line 552
    aput-object v22, v1, v2

    .line 553
    .line 554
    const/16 v2, 0x12

    .line 555
    .line 556
    aput-object v23, v1, v2

    .line 557
    .line 558
    const/16 v2, 0x13

    .line 559
    .line 560
    aput-object v24, v1, v2

    .line 561
    .line 562
    const/16 v2, 0x14

    .line 563
    .line 564
    aput-object v25, v1, v2

    .line 565
    .line 566
    const/16 v2, 0x15

    .line 567
    .line 568
    aput-object v26, v1, v2

    .line 569
    .line 570
    const/16 v2, 0x16

    .line 571
    .line 572
    aput-object v27, v1, v2

    .line 573
    .line 574
    const/16 v2, 0x17

    .line 575
    .line 576
    aput-object v28, v1, v2

    .line 577
    .line 578
    const/16 v2, 0x18

    .line 579
    .line 580
    aput-object v29, v1, v2

    .line 581
    .line 582
    const/16 v2, 0x19

    .line 583
    .line 584
    aput-object v30, v1, v2

    .line 585
    .line 586
    const/16 v2, 0x1a

    .line 587
    .line 588
    aput-object v31, v1, v2

    .line 589
    .line 590
    const/16 v2, 0x1b

    .line 591
    .line 592
    aput-object v32, v1, v2

    .line 593
    .line 594
    const/16 v2, 0x1c

    .line 595
    .line 596
    aput-object v33, v1, v2

    .line 597
    .line 598
    const/16 v2, 0x1d

    .line 599
    .line 600
    aput-object v34, v1, v2

    .line 601
    .line 602
    const/16 v2, 0x1e

    .line 603
    .line 604
    aput-object v35, v1, v2

    .line 605
    .line 606
    const/16 v2, 0x1f

    .line 607
    .line 608
    aput-object v36, v1, v2

    .line 609
    .line 610
    const/16 v2, 0x20

    .line 611
    .line 612
    aput-object v37, v1, v2

    .line 613
    .line 614
    const/16 v2, 0x21

    .line 615
    .line 616
    aput-object v38, v1, v2

    .line 617
    .line 618
    const/16 v2, 0x22

    .line 619
    .line 620
    aput-object v39, v1, v2

    .line 621
    .line 622
    const/16 v2, 0x23

    .line 623
    .line 624
    aput-object v40, v1, v2

    .line 625
    .line 626
    const/16 v2, 0x24

    .line 627
    .line 628
    aput-object v41, v1, v2

    .line 629
    .line 630
    const/16 v2, 0x25

    .line 631
    .line 632
    aput-object v42, v1, v2

    .line 633
    .line 634
    const/16 v2, 0x26

    .line 635
    .line 636
    aput-object v43, v1, v2

    .line 637
    .line 638
    const/16 v2, 0x27

    .line 639
    .line 640
    aput-object v44, v1, v2

    .line 641
    .line 642
    const/16 v2, 0x28

    .line 643
    .line 644
    aput-object v45, v1, v2

    .line 645
    .line 646
    const/16 v2, 0x29

    .line 647
    .line 648
    aput-object v46, v1, v2

    .line 649
    .line 650
    const/16 v2, 0x2a

    .line 651
    .line 652
    aput-object v47, v1, v2

    .line 653
    .line 654
    const/16 v2, 0x2b

    .line 655
    .line 656
    aput-object v48, v1, v2

    .line 657
    .line 658
    const/16 v2, 0x2c

    .line 659
    .line 660
    aput-object v49, v1, v2

    .line 661
    .line 662
    const/16 v2, 0x2d

    .line 663
    .line 664
    aput-object v50, v1, v2

    .line 665
    .line 666
    const/16 v2, 0x2e

    .line 667
    .line 668
    aput-object v51, v1, v2

    .line 669
    .line 670
    const/16 v2, 0x2f

    .line 671
    .line 672
    aput-object v52, v1, v2

    .line 673
    .line 674
    const/16 v2, 0x30

    .line 675
    .line 676
    aput-object v53, v1, v2

    .line 677
    .line 678
    const/16 v2, 0x31

    .line 679
    .line 680
    aput-object v0, v1, v2

    .line 681
    .line 682
    sput-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 683
    .line 684
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SOURCE_CODE_QUALIFIED;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy$SOURCE_CODE_QUALIFIED;

    .line 5
    .line 6
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->classifierNamePolicy$delegate:Ldy0/c;

    .line 11
    .line 12
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withDefinedIn$delegate:Ldy0/c;

    .line 19
    .line 20
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withSourceFileForTopLevel$delegate:Ldy0/c;

    .line 25
    .line 26
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;->ALL_EXCEPT_ANNOTATIONS:Ljava/util/Set;

    .line 27
    .line 28
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->modifiers$delegate:Ldy0/c;

    .line 33
    .line 34
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 35
    .line 36
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->startFromName$delegate:Ldy0/c;

    .line 41
    .line 42
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->startFromDeclarationKeyword$delegate:Ldy0/c;

    .line 47
    .line 48
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->debugMode$delegate:Ldy0/c;

    .line 53
    .line 54
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->classWithPrimaryConstructor$delegate:Ldy0/c;

    .line 59
    .line 60
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->verbose$delegate:Ldy0/c;

    .line 65
    .line 66
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->unitReturnType$delegate:Ldy0/c;

    .line 71
    .line 72
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutReturnType$delegate:Ldy0/c;

    .line 77
    .line 78
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->enhancedTypes$delegate:Ldy0/c;

    .line 83
    .line 84
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->normalizedVisibilities$delegate:Ldy0/c;

    .line 89
    .line 90
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultVisibility$delegate:Ldy0/c;

    .line 95
    .line 96
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultModality$delegate:Ldy0/c;

    .line 101
    .line 102
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderConstructorDelegation$delegate:Ldy0/c;

    .line 107
    .line 108
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderPrimaryConstructorParametersAsProperties$delegate:Ldy0/c;

    .line 113
    .line 114
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->actualPropertiesInPrimaryConstructor$delegate:Ldy0/c;

    .line 119
    .line 120
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->uninferredTypeParameterAsName$delegate:Ldy0/c;

    .line 125
    .line 126
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->includePropertyConstant$delegate:Ldy0/c;

    .line 131
    .line 132
    const/4 v2, 0x0

    .line 133
    invoke-direct {p0, v2}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->propertyConstantRenderer$delegate:Ldy0/c;

    .line 138
    .line 139
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutTypeParameters$delegate:Ldy0/c;

    .line 144
    .line 145
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutSuperTypes$delegate:Ldy0/c;

    .line 150
    .line 151
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$$Lambda$0;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$$Lambda$0;

    .line 152
    .line 153
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->typeNormalizer$delegate:Ldy0/c;

    .line 158
    .line 159
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$$Lambda$1;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$$Lambda$1;

    .line 160
    .line 161
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->defaultParameterValueRenderer$delegate:Ldy0/c;

    .line 166
    .line 167
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->secondaryConstructorsAsPrimary$delegate:Ldy0/c;

    .line 172
    .line 173
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/OverrideRenderingPolicy;->RENDER_OPEN:Lkotlin/reflect/jvm/internal/impl/renderer/OverrideRenderingPolicy;

    .line 174
    .line 175
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->overrideRenderingPolicy$delegate:Ldy0/c;

    .line 180
    .line 181
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$ValueParametersHandler$DEFAULT;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$ValueParametersHandler$DEFAULT;

    .line 182
    .line 183
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->valueParametersHandler$delegate:Ldy0/c;

    .line 188
    .line 189
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;->PLAIN:Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;

    .line 190
    .line 191
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 192
    .line 193
    .line 194
    move-result-object v3

    .line 195
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->textFormat$delegate:Ldy0/c;

    .line 196
    .line 197
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;->ALL:Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;

    .line 198
    .line 199
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 200
    .line 201
    .line 202
    move-result-object v3

    .line 203
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->parameterNameRenderingPolicy$delegate:Ldy0/c;

    .line 204
    .line 205
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->receiverAfterName$delegate:Ldy0/c;

    .line 210
    .line 211
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderCompanionObjectName$delegate:Ldy0/c;

    .line 216
    .line 217
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/PropertyAccessorRenderingPolicy;->DEBUG:Lkotlin/reflect/jvm/internal/impl/renderer/PropertyAccessorRenderingPolicy;

    .line 218
    .line 219
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->propertyAccessorRenderingPolicy$delegate:Ldy0/c;

    .line 224
    .line 225
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultAnnotationArguments$delegate:Ldy0/c;

    .line 230
    .line 231
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 232
    .line 233
    .line 234
    move-result-object v3

    .line 235
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->eachAnnotationOnNewLine$delegate:Ldy0/c;

    .line 236
    .line 237
    sget-object v3, Lmx0/u;->d:Lmx0/u;

    .line 238
    .line 239
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 240
    .line 241
    .line 242
    move-result-object v3

    .line 243
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->excludedAnnotationClasses$delegate:Ldy0/c;

    .line 244
    .line 245
    sget-object v3, Lkotlin/reflect/jvm/internal/impl/renderer/ExcludedTypeAnnotations;->INSTANCE:Lkotlin/reflect/jvm/internal/impl/renderer/ExcludedTypeAnnotations;

    .line 246
    .line 247
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/renderer/ExcludedTypeAnnotations;->getInternalAnnotationsForResolve()Ljava/util/Set;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    invoke-direct {p0, v3}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 252
    .line 253
    .line 254
    move-result-object v3

    .line 255
    iput-object v3, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->excludedTypeAnnotationClasses$delegate:Ldy0/c;

    .line 256
    .line 257
    invoke-direct {p0, v2}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 258
    .line 259
    .line 260
    move-result-object v2

    .line 261
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->annotationFilter$delegate:Ldy0/c;

    .line 262
    .line 263
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;->NO_ARGUMENTS:Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;

    .line 264
    .line 265
    invoke-direct {p0, v2}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 266
    .line 267
    .line 268
    move-result-object v2

    .line 269
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->annotationArgumentsRenderingPolicy$delegate:Ldy0/c;

    .line 270
    .line 271
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->alwaysRenderModifiers$delegate:Ldy0/c;

    .line 276
    .line 277
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderConstructorKeyword$delegate:Ldy0/c;

    .line 282
    .line 283
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 284
    .line 285
    .line 286
    move-result-object v2

    .line 287
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderUnabbreviatedType$delegate:Ldy0/c;

    .line 288
    .line 289
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 290
    .line 291
    .line 292
    move-result-object v2

    .line 293
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderTypeExpansions$delegate:Ldy0/c;

    .line 294
    .line 295
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 296
    .line 297
    .line 298
    move-result-object v2

    .line 299
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderAbbreviatedTypeComments$delegate:Ldy0/c;

    .line 300
    .line 301
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 302
    .line 303
    .line 304
    move-result-object v2

    .line 305
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->includeAdditionalModifiers$delegate:Ldy0/c;

    .line 306
    .line 307
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 308
    .line 309
    .line 310
    move-result-object v2

    .line 311
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->parameterNamesInFunctionalTypes$delegate:Ldy0/c;

    .line 312
    .line 313
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderFunctionContracts$delegate:Ldy0/c;

    .line 318
    .line 319
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    iput-object v2, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->presentableUnresolvedTypes$delegate:Ldy0/c;

    .line 324
    .line 325
    invoke-direct {p0, v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    iput-object v1, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->boldOnlyForNamesInHtml$delegate:Ldy0/c;

    .line 330
    .line 331
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->informativeErrorType$delegate:Ldy0/c;

    .line 336
    .line 337
    return-void
.end method

.method public static synthetic accessor$DescriptorRendererOptionsImpl$lambda0(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->typeNormalizer_delegate$lambda$0(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$DescriptorRendererOptionsImpl$lambda1(Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->defaultParameterValueRenderer_delegate$lambda$0(Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final defaultParameterValueRenderer_delegate$lambda$0(Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "..."

    .line 7
    .line 8
    return-object p0
.end method

.method private final property(Ljava/lang/Object;)Ldy0/c;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(TT;)",
            "Ldy0/c;"
        }
    .end annotation

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$property$$inlined$vetoable$1;

    .line 2
    .line 3
    invoke-direct {v0, p1, p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl$property$$inlined$vetoable$1;-><init>(Ljava/lang/Object;Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static final typeNormalizer_delegate$lambda$0(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method


# virtual methods
.method public final copy()Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;

    .line 4
    .line 5
    invoke-direct {v1}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;-><init>()V

    .line 6
    .line 7
    .line 8
    const-class v2, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;

    .line 9
    .line 10
    invoke-virtual {v2}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    const-string v4, "getDeclaredFields(...)"

    .line 15
    .line 16
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    array-length v4, v3

    .line 20
    const/4 v5, 0x0

    .line 21
    move v6, v5

    .line 22
    :goto_0
    if-ge v6, v4, :cond_4

    .line 23
    .line 24
    aget-object v7, v3, v6

    .line 25
    .line 26
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 27
    .line 28
    .line 29
    move-result v8

    .line 30
    and-int/lit8 v8, v8, 0x8

    .line 31
    .line 32
    if-nez v8, :cond_3

    .line 33
    .line 34
    const/4 v8, 0x1

    .line 35
    invoke-virtual {v7, v8}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v7, v0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v9

    .line 42
    instance-of v10, v9, Ldy0/a;

    .line 43
    .line 44
    if-eqz v10, :cond_0

    .line 45
    .line 46
    check-cast v9, Ldy0/a;

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_0
    const/4 v9, 0x0

    .line 50
    :goto_1
    if-nez v9, :cond_1

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_1
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v10

    .line 57
    const-string v11, "getName(...)"

    .line 58
    .line 59
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    const-string v12, "is"

    .line 63
    .line 64
    invoke-static {v10, v12, v5}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 65
    .line 66
    .line 67
    sget-object v10, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 68
    .line 69
    invoke-virtual {v10, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 70
    .line 71
    .line 72
    move-result-object v10

    .line 73
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v15

    .line 77
    new-instance v12, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    const-string v13, "get"

    .line 80
    .line 81
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v13

    .line 88
    invoke-static {v13, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v13}, Ljava/lang/String;->length()I

    .line 92
    .line 93
    .line 94
    move-result v11

    .line 95
    if-lez v11, :cond_2

    .line 96
    .line 97
    invoke-virtual {v13, v5}, Ljava/lang/String;->charAt(I)C

    .line 98
    .line 99
    .line 100
    move-result v11

    .line 101
    invoke-static {v11}, Ljava/lang/Character;->toUpperCase(C)C

    .line 102
    .line 103
    .line 104
    move-result v11

    .line 105
    invoke-virtual {v13, v8}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v13

    .line 109
    const-string v14, "substring(...)"

    .line 110
    .line 111
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    new-instance v14, Ljava/lang/StringBuilder;

    .line 115
    .line 116
    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v14, v11}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v14, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v13

    .line 129
    :cond_2
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v16

    .line 136
    new-instance v12, Lkotlin/jvm/internal/x;

    .line 137
    .line 138
    sget-object v13, Lkotlin/jvm/internal/d;->NO_RECEIVER:Ljava/lang/Object;

    .line 139
    .line 140
    move-object v11, v10

    .line 141
    check-cast v11, Lkotlin/jvm/internal/e;

    .line 142
    .line 143
    invoke-interface {v11}, Lkotlin/jvm/internal/e;->getJClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    move-result-object v14

    .line 147
    invoke-static {v10}, Ljava/util/Objects;->nonNull(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v10

    .line 151
    xor-int/lit8 v17, v10, 0x1

    .line 152
    .line 153
    invoke-direct/range {v12 .. v17}, Lkotlin/jvm/internal/a0;-><init>(Ljava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v9, v0, v12}, Ldy0/a;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    invoke-direct {v1, v8}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->property(Ljava/lang/Object;)Ldy0/c;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    invoke-virtual {v7, v1, v8}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :cond_3
    :goto_2
    add-int/lit8 v6, v6, 0x1

    .line 168
    .line 169
    goto/16 :goto_0

    .line 170
    .line 171
    :cond_4
    return-object v1
.end method

.method public getActualPropertiesInPrimaryConstructor()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->actualPropertiesInPrimaryConstructor$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x11

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getAlwaysRenderModifiers()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->alwaysRenderModifiers$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x27

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getAnnotationArgumentsRenderingPolicy()Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->annotationArgumentsRenderingPolicy$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x26

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;

    .line 14
    .line 15
    return-object p0
.end method

.method public getAnnotationFilter()Lay0/k;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->annotationFilter$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x25

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lay0/k;

    .line 14
    .line 15
    return-object p0
.end method

.method public getBoldOnlyForNamesInHtml()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->boldOnlyForNamesInHtml$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x30

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getClassWithPrimaryConstructor()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->classWithPrimaryConstructor$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getClassifierNamePolicy()Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->classifierNamePolicy$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;

    .line 13
    .line 14
    return-object p0
.end method

.method public getDebugMode()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->debugMode$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getDefaultParameterValueRenderer()Lay0/k;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->defaultParameterValueRenderer$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x18

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lay0/k;

    .line 14
    .line 15
    return-object p0
.end method

.method public getEachAnnotationOnNewLine()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->eachAnnotationOnNewLine$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x22

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getEnhancedTypes()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->enhancedTypes$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xb

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getExcludedAnnotationClasses()Ljava/util/Set;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->excludedAnnotationClasses$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x23

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/util/Set;

    .line 14
    .line 15
    return-object p0
.end method

.method public getExcludedTypeAnnotationClasses()Ljava/util/Set;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->excludedTypeAnnotationClasses$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x24

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/util/Set;

    .line 14
    .line 15
    return-object p0
.end method

.method public getIncludeAdditionalModifiers()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->includeAdditionalModifiers$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x2c

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public bridge getIncludeAnnotationArguments()Z
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions$DefaultImpls;->getIncludeAnnotationArguments(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public bridge getIncludeEmptyAnnotationArguments()Z
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions$DefaultImpls;->getIncludeEmptyAnnotationArguments(Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getIncludePropertyConstant()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->includePropertyConstant$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x13

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getInformativeErrorType()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->informativeErrorType$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x31

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getModifiers()Ljava/util/Set;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->modifiers$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/util/Set;

    .line 13
    .line 14
    return-object p0
.end method

.method public getNormalizedVisibilities()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->normalizedVisibilities$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xc

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getOverrideRenderingPolicy()Lkotlin/reflect/jvm/internal/impl/renderer/OverrideRenderingPolicy;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->overrideRenderingPolicy$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1a

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/OverrideRenderingPolicy;

    .line 14
    .line 15
    return-object p0
.end method

.method public getParameterNameRenderingPolicy()Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->parameterNameRenderingPolicy$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1d

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;

    .line 14
    .line 15
    return-object p0
.end method

.method public getParameterNamesInFunctionalTypes()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->parameterNamesInFunctionalTypes$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x2d

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getPresentableUnresolvedTypes()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->presentableUnresolvedTypes$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x2f

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getPropertyAccessorRenderingPolicy()Lkotlin/reflect/jvm/internal/impl/renderer/PropertyAccessorRenderingPolicy;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->propertyAccessorRenderingPolicy$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/PropertyAccessorRenderingPolicy;

    .line 14
    .line 15
    return-object p0
.end method

.method public getPropertyConstantRenderer()Lay0/k;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->propertyConstantRenderer$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x14

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lay0/k;

    .line 14
    .line 15
    return-object p0
.end method

.method public getReceiverAfterName()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->receiverAfterName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1e

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderAbbreviatedTypeComments()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderAbbreviatedTypeComments$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x2b

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderCompanionObjectName()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderCompanionObjectName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderConstructorDelegation()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderConstructorDelegation$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xf

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderConstructorKeyword()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderConstructorKeyword$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x28

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderDefaultAnnotationArguments()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultAnnotationArguments$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x21

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderDefaultModality()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultModality$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xe

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderDefaultVisibility()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderDefaultVisibility$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xd

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderPrimaryConstructorParametersAsProperties()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderPrimaryConstructorParametersAsProperties$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x10

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderTypeExpansions()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderTypeExpansions$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x2a

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getRenderUnabbreviatedType()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderUnabbreviatedType$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x29

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getSecondaryConstructorsAsPrimary()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->secondaryConstructorsAsPrimary$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x19

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getStartFromDeclarationKeyword()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->startFromDeclarationKeyword$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getStartFromName()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->startFromName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getTextFormat()Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->textFormat$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1c

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;

    .line 14
    .line 15
    return-object p0
.end method

.method public getTypeNormalizer()Lay0/k;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->typeNormalizer$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x17

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lay0/k;

    .line 14
    .line 15
    return-object p0
.end method

.method public getUninferredTypeParameterAsName()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->uninferredTypeParameterAsName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x12

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getUnitReturnType()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->unitReturnType$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x9

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getValueParametersHandler()Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$ValueParametersHandler;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->valueParametersHandler$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1b

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRenderer$ValueParametersHandler;

    .line 14
    .line 15
    return-object p0
.end method

.method public getVerbose()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->verbose$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x8

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getWithDefinedIn()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withDefinedIn$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getWithSourceFileForTopLevel()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withSourceFileForTopLevel$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0
.end method

.method public getWithoutReturnType()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutReturnType$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getWithoutSuperTypes()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutSuperTypes$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x16

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public getWithoutTypeParameters()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutTypeParameters$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x15

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ldy0/b;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final isLocked()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->isLocked:Z

    .line 2
    .line 3
    return p0
.end method

.method public final lock()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->isLocked:Z

    .line 3
    .line 4
    return-void
.end method

.method public setAnnotationArgumentsRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;)V
    .locals 3

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->annotationArgumentsRenderingPolicy$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/16 v2, 0x26

    .line 11
    .line 12
    aget-object v1, v1, v2

    .line 13
    .line 14
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V
    .locals 3

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->classifierNamePolicy$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    aget-object v1, v1, v2

    .line 12
    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setDebugMode(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->debugMode$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public setExcludedTypeAnnotationClasses(Ljava/util/Set;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->excludedTypeAnnotationClasses$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/16 v2, 0x24

    .line 11
    .line 12
    aget-object v1, v1, v2

    .line 13
    .line 14
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setModifiers(Ljava/util/Set;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->modifiers$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    aget-object v1, v1, v2

    .line 12
    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setParameterNameRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;)V
    .locals 3

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->parameterNameRenderingPolicy$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/16 v2, 0x1d

    .line 11
    .line 12
    aget-object v1, v1, v2

    .line 13
    .line 14
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setReceiverAfterName(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->receiverAfterName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1e

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setRenderCompanionObjectName(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->renderCompanionObjectName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setStartFromName(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->startFromName$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public setTextFormat(Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;)V
    .locals 3

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->textFormat$delegate:Ldy0/c;

    .line 7
    .line 8
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 9
    .line 10
    const/16 v2, 0x1c

    .line 11
    .line 12
    aget-object v1, v1, v2

    .line 13
    .line 14
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public setVerbose(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->verbose$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x8

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setWithDefinedIn(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withDefinedIn$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public setWithoutSuperTypes(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutSuperTypes$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x16

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public setWithoutTypeParameters(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->withoutTypeParameters$delegate:Ldy0/c;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptionsImpl;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/16 v2, 0x15

    .line 6
    .line 7
    aget-object v1, v1, v2

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {v0, p0, v1, p1}, Ldy0/c;->setValue(Ljava/lang/Object;Lhy0/z;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
