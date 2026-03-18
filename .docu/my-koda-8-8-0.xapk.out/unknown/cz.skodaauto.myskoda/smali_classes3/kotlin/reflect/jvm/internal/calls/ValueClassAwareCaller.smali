.class public final Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/calls/Caller;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;,
        Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$MultiFieldValueClassPrimaryConstructorCaller;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<M::",
        "Ljava/lang/reflect/Member;",
        ">",
        "Ljava/lang/Object;",
        "Lkotlin/reflect/jvm/internal/calls/Caller<",
        "TM;>;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010 \n\u0002\u0008\u0008\u0008\u0000\u0018\u0000*\u000c\u0008\u0000\u0010\u0002 \u0001*\u0004\u0018\u00010\u00012\u0008\u0012\u0004\u0012\u00028\u00000\u0003:\u0002,-B%\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u000c\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u0003\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0015\u0010\u000e\u001a\u00020\r2\u0006\u0010\u000c\u001a\u00020\u000b\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u001d\u0010\u0013\u001a\u0004\u0018\u00010\u00122\n\u0010\u0011\u001a\u0006\u0012\u0002\u0008\u00030\u0010H\u0016\u00a2\u0006\u0004\u0008\u0013\u0010\u0014R\u0014\u0010\u0008\u001a\u00020\u00078\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0008\u0010\u0015R\u001a\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u00038\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0016\u0010\u0017R\u001a\u0010\u0018\u001a\u00028\u00008\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0018\u0010\u0019\u001a\u0004\u0008\u001a\u0010\u001bR\u0014\u0010\u001d\u001a\u00020\u001c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001d\u0010\u001eR\u001a\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\r0\u00108\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001f\u0010 R\u0014\u0010!\u001a\u00020\u00078\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008!\u0010\u0015R\u0014\u0010%\u001a\u00020\"8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008#\u0010$R\u001a\u0010)\u001a\u0008\u0012\u0004\u0012\u00020\"0&8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\'\u0010(R\u0014\u0010*\u001a\u00020\u00078VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008*\u0010+\u00a8\u0006."
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;",
        "Ljava/lang/reflect/Member;",
        "M",
        "Lkotlin/reflect/jvm/internal/calls/Caller;",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;",
        "descriptor",
        "oldCaller",
        "",
        "isDefault",
        "<init>",
        "(Lorg/jetbrains/kotlin/descriptors/CallableMemberDescriptor;Lkotlin/reflect/jvm/internal/calls/Caller;Z)V",
        "",
        "index",
        "Lgy0/j;",
        "getRealSlicesOfParameters",
        "(I)Lgy0/j;",
        "",
        "args",
        "",
        "call",
        "([Ljava/lang/Object;)Ljava/lang/Object;",
        "Z",
        "caller",
        "Lkotlin/reflect/jvm/internal/calls/Caller;",
        "member",
        "Ljava/lang/reflect/Member;",
        "getMember",
        "()Ljava/lang/reflect/Member;",
        "Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;",
        "data",
        "Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;",
        "slices",
        "[Lgy0/j;",
        "hasMfvcParameters",
        "Ljava/lang/reflect/Type;",
        "getReturnType",
        "()Ljava/lang/reflect/Type;",
        "returnType",
        "",
        "getParameterTypes",
        "()Ljava/util/List;",
        "parameterTypes",
        "isBoundInstanceCallWithValueClasses",
        "()Z",
        "BoxUnboxData",
        "MultiFieldValueClassPrimaryConstructorCaller",
        "kotlin-reflection"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final caller:Lkotlin/reflect/jvm/internal/calls/Caller;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/reflect/jvm/internal/calls/Caller<",
            "TM;>;"
        }
    .end annotation
.end field

.field private final data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

.field private final hasMfvcParameters:Z

.field private final isDefault:Z

.field private final member:Ljava/lang/reflect/Member;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TM;"
        }
    .end annotation
.end field

.field private final slices:[Lgy0/j;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Lkotlin/reflect/jvm/internal/calls/Caller;Z)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;",
            "Lkotlin/reflect/jvm/internal/calls/Caller<",
            "+TM;>;Z)V"
        }
    .end annotation

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "oldCaller"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-boolean p3, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->isDefault:Z

    .line 15
    .line 16
    instance-of v0, p2, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    const/4 v2, 0x0

    .line 20
    if-eqz v0, :cond_6

    .line 21
    .line 22
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getExtensionReceiverParameter()Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getDispatchReceiverParameter()Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :cond_0
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-interface {v0}, Lkotlin/reflect/jvm/internal/impl/descriptors/ValueDescriptor;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move-object v0, v1

    .line 40
    :goto_0
    if-eqz v0, :cond_6

    .line 41
    .line 42
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/resolve/InlineClassesUtilsKt;->needsMfvcFlattening(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_6

    .line 47
    .line 48
    if-eqz p3, :cond_4

    .line 49
    .line 50
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getValueParameters()Ljava/util/List;

    .line 51
    .line 52
    .line 53
    move-result-object p3

    .line 54
    const-string v3, "getValueParameters(...)"

    .line 55
    .line 56
    invoke-static {p3, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    check-cast p3, Ljava/lang/Iterable;

    .line 60
    .line 61
    instance-of v3, p3, Ljava/util/Collection;

    .line 62
    .line 63
    if-eqz v3, :cond_2

    .line 64
    .line 65
    move-object v3, p3

    .line 66
    check-cast v3, Ljava/util/Collection;

    .line 67
    .line 68
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    if-eqz v3, :cond_2

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_2
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object p3

    .line 79
    :cond_3
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_6

    .line 84
    .line 85
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;

    .line 90
    .line 91
    invoke-interface {v3}, Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;->declaresDefaultValue()Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-eqz v3, :cond_3

    .line 96
    .line 97
    :cond_4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->asSimpleType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 98
    .line 99
    .line 100
    move-result-object p3

    .line 101
    invoke-static {p3}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->getMfvcUnboxMethods(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;)Ljava/util/List;

    .line 102
    .line 103
    .line 104
    move-result-object p3

    .line 105
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    check-cast p3, Ljava/lang/Iterable;

    .line 109
    .line 110
    new-instance v0, Ljava/util/ArrayList;

    .line 111
    .line 112
    const/16 v3, 0xa

    .line 113
    .line 114
    invoke-static {p3, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 122
    .line 123
    .line 124
    move-result-object p3

    .line 125
    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    if-eqz v3, :cond_5

    .line 130
    .line 131
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    check-cast v3, Ljava/lang/reflect/Method;

    .line 136
    .line 137
    move-object v4, p2

    .line 138
    check-cast v4, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;

    .line 139
    .line 140
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;->getBoundReceiver$kotlin_reflection()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    invoke-virtual {v3, v4, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_5
    new-array p3, v2, [Ljava/lang/Object;

    .line 153
    .line 154
    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p3

    .line 158
    new-instance v0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 159
    .line 160
    check-cast p2, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;

    .line 161
    .line 162
    invoke-virtual {p2}, Lkotlin/reflect/jvm/internal/calls/CallerImpl;->getMember()Ljava/lang/reflect/Member;

    .line 163
    .line 164
    .line 165
    move-result-object p2

    .line 166
    check-cast p2, Ljava/lang/reflect/Method;

    .line 167
    .line 168
    invoke-direct {v0, p2, p3}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;-><init>(Ljava/lang/reflect/Method;[Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-object p2, v0

    .line 172
    :cond_6
    :goto_2
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 173
    .line 174
    invoke-interface {p2}, Lkotlin/reflect/jvm/internal/calls/Caller;->getMember()Ljava/lang/reflect/Member;

    .line 175
    .line 176
    .line 177
    move-result-object p3

    .line 178
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->member:Ljava/lang/reflect/Member;

    .line 179
    .line 180
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getReturnType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 181
    .line 182
    .line 183
    move-result-object p3

    .line 184
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;

    .line 188
    .line 189
    const/4 v3, 0x1

    .line 190
    if-eqz v0, :cond_8

    .line 191
    .line 192
    move-object v4, p1

    .line 193
    check-cast v4, Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;

    .line 194
    .line 195
    invoke-interface {v4}, Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;->isSuspend()Z

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    if-eqz v4, :cond_8

    .line 200
    .line 201
    invoke-static {p3}, Lkotlin/reflect/jvm/internal/impl/resolve/InlineClassesUtilsKt;->unsubstitutedUnderlyingType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    if-eqz v4, :cond_8

    .line 206
    .line 207
    invoke-static {v4}, Lkotlin/reflect/jvm/internal/impl/builtins/KotlinBuiltIns;->isPrimitiveType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Z

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    if-ne v4, v3, :cond_8

    .line 212
    .line 213
    :cond_7
    move-object p3, v1

    .line 214
    goto :goto_3

    .line 215
    :cond_8
    invoke-static {p3}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->access$toInlineClass(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    move-result-object p3

    .line 219
    if-eqz p3, :cond_7

    .line 220
    .line 221
    invoke-static {p3, p1}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->access$getBoxMethod(Ljava/lang/Class;Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;)Ljava/lang/reflect/Method;

    .line 222
    .line 223
    .line 224
    move-result-object p3

    .line 225
    :goto_3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/resolve/InlineClassesUtilsKt;->isGetterOfUnderlyingPropertyOfValueClass(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;)Z

    .line 226
    .line 227
    .line 228
    move-result v4

    .line 229
    if-eqz v4, :cond_9

    .line 230
    .line 231
    new-instance p1, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 232
    .line 233
    sget-object p2, Lgy0/j;->g:Lgy0/j;

    .line 234
    .line 235
    new-array v0, v2, [Ljava/util/List;

    .line 236
    .line 237
    invoke-direct {p1, p2, v0, p3}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;-><init>(Lgy0/j;[Ljava/util/List;Ljava/lang/reflect/Method;)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_d

    .line 241
    .line 242
    :cond_9
    instance-of v4, p2, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;

    .line 243
    .line 244
    const/4 v5, -0x1

    .line 245
    if-eqz v4, :cond_a

    .line 246
    .line 247
    move-object v4, p2

    .line 248
    check-cast v4, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;

    .line 249
    .line 250
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;->isCallByToValueClassMangledMethod$kotlin_reflection()Z

    .line 251
    .line 252
    .line 253
    move-result v4

    .line 254
    if-nez v4, :cond_a

    .line 255
    .line 256
    goto :goto_5

    .line 257
    :cond_a
    instance-of v4, p2, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 258
    .line 259
    if-eqz v4, :cond_b

    .line 260
    .line 261
    goto :goto_5

    .line 262
    :cond_b
    instance-of v4, p1, Lkotlin/reflect/jvm/internal/impl/descriptors/ConstructorDescriptor;

    .line 263
    .line 264
    if-eqz v4, :cond_d

    .line 265
    .line 266
    instance-of v4, p2, Lkotlin/reflect/jvm/internal/calls/BoundCaller;

    .line 267
    .line 268
    if-eqz v4, :cond_c

    .line 269
    .line 270
    goto :goto_5

    .line 271
    :cond_c
    :goto_4
    move v5, v2

    .line 272
    goto :goto_5

    .line 273
    :cond_d
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getDispatchReceiverParameter()Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    if-eqz v4, :cond_c

    .line 278
    .line 279
    instance-of v4, p2, Lkotlin/reflect/jvm/internal/calls/BoundCaller;

    .line 280
    .line 281
    if-nez v4, :cond_c

    .line 282
    .line 283
    invoke-interface {p1}, Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptorNonRoot;->getContainingDeclaration()Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;

    .line 284
    .line 285
    .line 286
    move-result-object v4

    .line 287
    const-string v5, "getContainingDeclaration(...)"

    .line 288
    .line 289
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-static {v4}, Lkotlin/reflect/jvm/internal/impl/resolve/InlineClassesUtilsKt;->isValueClass(Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;)Z

    .line 293
    .line 294
    .line 295
    move-result v4

    .line 296
    if-eqz v4, :cond_e

    .line 297
    .line 298
    goto :goto_4

    .line 299
    :cond_e
    move v5, v3

    .line 300
    :goto_5
    instance-of v4, p2, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 301
    .line 302
    if-eqz v4, :cond_f

    .line 303
    .line 304
    move-object v4, p2

    .line 305
    check-cast v4, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 306
    .line 307
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->getReceiverComponentsCount()I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    neg-int v4, v4

    .line 312
    goto :goto_6

    .line 313
    :cond_f
    move v4, v5

    .line 314
    :goto_6
    invoke-interface {p2}, Lkotlin/reflect/jvm/internal/calls/Caller;->getMember()Ljava/lang/reflect/Member;

    .line 315
    .line 316
    .line 317
    move-result-object p2

    .line 318
    sget-object v6, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$$Lambda$0;->INSTANCE:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$$Lambda$0;

    .line 319
    .line 320
    invoke-static {p1, p2, v6}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->access$makeKotlinParameterTypes(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Ljava/lang/reflect/Member;Lay0/k;)Ljava/util/List;

    .line 321
    .line 322
    .line 323
    move-result-object p2

    .line 324
    move-object v6, p2

    .line 325
    check-cast v6, Ljava/lang/Iterable;

    .line 326
    .line 327
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 328
    .line 329
    .line 330
    move-result-object v6

    .line 331
    move v7, v2

    .line 332
    :goto_7
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 333
    .line 334
    .line 335
    move-result v8

    .line 336
    if-eqz v8, :cond_11

    .line 337
    .line 338
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v8

    .line 342
    check-cast v8, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 343
    .line 344
    invoke-static {v8}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->asSimpleType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 345
    .line 346
    .line 347
    move-result-object v8

    .line 348
    invoke-static {v8}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->getMfvcUnboxMethods(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;)Ljava/util/List;

    .line 349
    .line 350
    .line 351
    move-result-object v8

    .line 352
    if-eqz v8, :cond_10

    .line 353
    .line 354
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 355
    .line 356
    .line 357
    move-result v8

    .line 358
    goto :goto_8

    .line 359
    :cond_10
    move v8, v3

    .line 360
    :goto_8
    add-int/2addr v7, v8

    .line 361
    goto :goto_7

    .line 362
    :cond_11
    iget-boolean v6, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->isDefault:Z

    .line 363
    .line 364
    if-eqz v6, :cond_12

    .line 365
    .line 366
    add-int/lit8 v6, v7, 0x1f

    .line 367
    .line 368
    div-int/lit8 v6, v6, 0x20

    .line 369
    .line 370
    add-int/2addr v6, v3

    .line 371
    goto :goto_9

    .line 372
    :cond_12
    move v6, v2

    .line 373
    :goto_9
    if-eqz v0, :cond_13

    .line 374
    .line 375
    move-object v0, p1

    .line 376
    check-cast v0, Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;

    .line 377
    .line 378
    invoke-interface {v0}, Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;->isSuspend()Z

    .line 379
    .line 380
    .line 381
    move-result v0

    .line 382
    if-eqz v0, :cond_13

    .line 383
    .line 384
    move v0, v3

    .line 385
    goto :goto_a

    .line 386
    :cond_13
    move v0, v2

    .line 387
    :goto_a
    add-int/2addr v6, v0

    .line 388
    add-int/2addr v7, v4

    .line 389
    add-int/2addr v7, v6

    .line 390
    iget-boolean v0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->isDefault:Z

    .line 391
    .line 392
    invoke-static {p0, v7, p1, v0}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->access$checkParametersSize(Lkotlin/reflect/jvm/internal/calls/Caller;ILkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;Z)V

    .line 393
    .line 394
    .line 395
    invoke-static {v5, v2}, Ljava/lang/Math;->max(II)I

    .line 396
    .line 397
    .line 398
    move-result v0

    .line 399
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 400
    .line 401
    .line 402
    move-result v4

    .line 403
    add-int/2addr v4, v5

    .line 404
    invoke-static {v0, v4}, Lkp/r9;->m(II)Lgy0/j;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    new-array v4, v7, [Ljava/util/List;

    .line 409
    .line 410
    move v6, v2

    .line 411
    :goto_b
    if-ge v6, v7, :cond_15

    .line 412
    .line 413
    iget v8, v0, Lgy0/h;->d:I

    .line 414
    .line 415
    iget v9, v0, Lgy0/h;->e:I

    .line 416
    .line 417
    if-gt v6, v9, :cond_14

    .line 418
    .line 419
    if-gt v8, v6, :cond_14

    .line 420
    .line 421
    sub-int v8, v6, v5

    .line 422
    .line 423
    invoke-interface {p2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v8

    .line 427
    check-cast v8, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 428
    .line 429
    invoke-static {v8}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->asSimpleType(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 430
    .line 431
    .line 432
    move-result-object v8

    .line 433
    invoke-static {v8, p1}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCallerKt;->access$getValueClassUnboxMethods(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;)Ljava/util/List;

    .line 434
    .line 435
    .line 436
    move-result-object v8

    .line 437
    goto :goto_c

    .line 438
    :cond_14
    move-object v8, v1

    .line 439
    :goto_c
    aput-object v8, v4, v6

    .line 440
    .line 441
    add-int/lit8 v6, v6, 0x1

    .line 442
    .line 443
    goto :goto_b

    .line 444
    :cond_15
    new-instance p1, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 445
    .line 446
    invoke-direct {p1, v0, v4, p3}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;-><init>(Lgy0/j;[Ljava/util/List;Ljava/lang/reflect/Method;)V

    .line 447
    .line 448
    .line 449
    :goto_d
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 450
    .line 451
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 452
    .line 453
    .line 454
    move-result-object p2

    .line 455
    iget-object p3, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 456
    .line 457
    instance-of v0, p3, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 458
    .line 459
    if-eqz v0, :cond_16

    .line 460
    .line 461
    check-cast p3, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;

    .line 462
    .line 463
    invoke-virtual {p3}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->getBoundReceiverComponents$kotlin_reflection()[Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object p3

    .line 467
    array-length p3, p3

    .line 468
    goto :goto_e

    .line 469
    :cond_16
    instance-of p3, p3, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStatic;

    .line 470
    .line 471
    if-eqz p3, :cond_17

    .line 472
    .line 473
    move p3, v3

    .line 474
    goto :goto_e

    .line 475
    :cond_17
    move p3, v2

    .line 476
    :goto_e
    if-lez p3, :cond_18

    .line 477
    .line 478
    invoke-static {v2, p3}, Lkp/r9;->m(II)Lgy0/j;

    .line 479
    .line 480
    .line 481
    move-result-object v0

    .line 482
    invoke-virtual {p2, v0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 483
    .line 484
    .line 485
    :cond_18
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getUnboxParameters()[Ljava/util/List;

    .line 486
    .line 487
    .line 488
    move-result-object p1

    .line 489
    array-length v0, p1

    .line 490
    move v1, v2

    .line 491
    :goto_f
    if-ge v1, v0, :cond_1a

    .line 492
    .line 493
    aget-object v4, p1, v1

    .line 494
    .line 495
    if-eqz v4, :cond_19

    .line 496
    .line 497
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 498
    .line 499
    .line 500
    move-result v4

    .line 501
    goto :goto_10

    .line 502
    :cond_19
    move v4, v3

    .line 503
    :goto_10
    add-int/2addr v4, p3

    .line 504
    invoke-static {p3, v4}, Lkp/r9;->m(II)Lgy0/j;

    .line 505
    .line 506
    .line 507
    move-result-object p3

    .line 508
    invoke-virtual {p2, p3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 509
    .line 510
    .line 511
    add-int/lit8 v1, v1, 0x1

    .line 512
    .line 513
    move p3, v4

    .line 514
    goto :goto_f

    .line 515
    :cond_1a
    invoke-static {p2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 516
    .line 517
    .line 518
    move-result-object p1

    .line 519
    new-array p2, v2, [Lgy0/j;

    .line 520
    .line 521
    invoke-virtual {p1, p2}, Lnx0/c;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object p1

    .line 525
    check-cast p1, [Lgy0/j;

    .line 526
    .line 527
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->slices:[Lgy0/j;

    .line 528
    .line 529
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 530
    .line 531
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getArgumentRange()Lgy0/j;

    .line 532
    .line 533
    .line 534
    move-result-object p1

    .line 535
    instance-of p2, p1, Ljava/util/Collection;

    .line 536
    .line 537
    if-eqz p2, :cond_1b

    .line 538
    .line 539
    move-object p2, p1

    .line 540
    check-cast p2, Ljava/util/Collection;

    .line 541
    .line 542
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 543
    .line 544
    .line 545
    move-result p2

    .line 546
    if-eqz p2, :cond_1b

    .line 547
    .line 548
    goto :goto_12

    .line 549
    :cond_1b
    invoke-virtual {p1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 550
    .line 551
    .line 552
    move-result-object p1

    .line 553
    :cond_1c
    :goto_11
    move-object p2, p1

    .line 554
    check-cast p2, Lgy0/i;

    .line 555
    .line 556
    iget-boolean p2, p2, Lgy0/i;->f:Z

    .line 557
    .line 558
    if-eqz p2, :cond_1e

    .line 559
    .line 560
    move-object p2, p1

    .line 561
    check-cast p2, Lmx0/w;

    .line 562
    .line 563
    invoke-virtual {p2}, Lmx0/w;->nextInt()I

    .line 564
    .line 565
    .line 566
    move-result p2

    .line 567
    iget-object p3, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 568
    .line 569
    invoke-virtual {p3}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getUnboxParameters()[Ljava/util/List;

    .line 570
    .line 571
    .line 572
    move-result-object p3

    .line 573
    aget-object p2, p3, p2

    .line 574
    .line 575
    if-nez p2, :cond_1d

    .line 576
    .line 577
    goto :goto_11

    .line 578
    :cond_1d
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 579
    .line 580
    .line 581
    move-result p2

    .line 582
    if-le p2, v3, :cond_1c

    .line 583
    .line 584
    move v2, v3

    .line 585
    :cond_1e
    :goto_12
    iput-boolean v2, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->hasMfvcParameters:Z

    .line 586
    .line 587
    return-void
.end method

.method public static synthetic accessor$ValueClassAwareCaller$lambda0(Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data$lambda$0$1(Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final data$lambda$0$1(Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;)Z
    .locals 1

    .line 1
    const-string v0, "$this$makeKotlinParameterTypes"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/impl/resolve/InlineClassesUtilsKt;->isValueClass(Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method


# virtual methods
.method public call([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    const-string v0, "args"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 7
    .line 8
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getArgumentRange()Lgy0/j;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 13
    .line 14
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getUnboxParameters()[Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->data:Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;

    .line 19
    .line 20
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller$BoxUnboxData;->getBox()Ljava/lang/reflect/Method;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    invoke-virtual {v0}, Lgy0/j;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    iget v4, v0, Lgy0/h;->e:I

    .line 29
    .line 30
    iget v0, v0, Lgy0/h;->d:I

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    goto/16 :goto_8

    .line 36
    .line 37
    :cond_0
    iget-boolean v3, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->hasMfvcParameters:Z

    .line 38
    .line 39
    const-string v6, "getReturnType(...)"

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    if-eqz v3, :cond_7

    .line 43
    .line 44
    array-length v3, p1

    .line 45
    new-instance v8, Lnx0/c;

    .line 46
    .line 47
    invoke-direct {v8, v3}, Lnx0/c;-><init>(I)V

    .line 48
    .line 49
    .line 50
    move v3, v7

    .line 51
    :goto_0
    if-ge v3, v0, :cond_1

    .line 52
    .line 53
    aget-object v9, p1, v3

    .line 54
    .line 55
    invoke-virtual {v8, v9}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    add-int/lit8 v3, v3, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    if-gt v0, v4, :cond_5

    .line 62
    .line 63
    :goto_1
    aget-object v3, v1, v0

    .line 64
    .line 65
    aget-object v9, p1, v0

    .line 66
    .line 67
    if-eqz v3, :cond_3

    .line 68
    .line 69
    check-cast v3, Ljava/lang/Iterable;

    .line 70
    .line 71
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    if-eqz v10, :cond_4

    .line 80
    .line 81
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v10

    .line 85
    check-cast v10, Ljava/lang/reflect/Method;

    .line 86
    .line 87
    if-eqz v9, :cond_2

    .line 88
    .line 89
    invoke-virtual {v10, v9, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v10

    .line 93
    goto :goto_3

    .line 94
    :cond_2
    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    move-result-object v10

    .line 98
    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-static {v10}, Lkotlin/reflect/jvm/internal/UtilKt;->defaultPrimitiveValue(Ljava/lang/reflect/Type;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v10

    .line 105
    :goto_3
    invoke-virtual {v8, v10}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_3
    invoke-virtual {v8, v9}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    :cond_4
    if-eq v0, v4, :cond_5

    .line 113
    .line 114
    add-int/lit8 v0, v0, 0x1

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_5
    add-int/lit8 v4, v4, 0x1

    .line 118
    .line 119
    array-length v0, p1

    .line 120
    add-int/lit8 v0, v0, -0x1

    .line 121
    .line 122
    if-gt v4, v0, :cond_6

    .line 123
    .line 124
    :goto_4
    aget-object v1, p1, v4

    .line 125
    .line 126
    invoke-virtual {v8, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    if-eq v4, v0, :cond_6

    .line 130
    .line 131
    add-int/lit8 v4, v4, 0x1

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_6
    invoke-static {v8}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    new-array v0, v7, [Ljava/lang/Object;

    .line 139
    .line 140
    invoke-virtual {p1, v0}, Lnx0/c;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    goto :goto_8

    .line 145
    :cond_7
    array-length v3, p1

    .line 146
    new-array v8, v3, [Ljava/lang/Object;

    .line 147
    .line 148
    :goto_5
    if-ge v7, v3, :cond_c

    .line 149
    .line 150
    if-gt v7, v4, :cond_b

    .line 151
    .line 152
    if-gt v0, v7, :cond_b

    .line 153
    .line 154
    aget-object v9, v1, v7

    .line 155
    .line 156
    if-eqz v9, :cond_8

    .line 157
    .line 158
    invoke-static {v9}, Lmx0/q;->i0(Ljava/util/List;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    check-cast v9, Ljava/lang/reflect/Method;

    .line 163
    .line 164
    goto :goto_6

    .line 165
    :cond_8
    move-object v9, v5

    .line 166
    :goto_6
    aget-object v10, p1, v7

    .line 167
    .line 168
    if-nez v9, :cond_9

    .line 169
    .line 170
    goto :goto_7

    .line 171
    :cond_9
    if-eqz v10, :cond_a

    .line 172
    .line 173
    invoke-virtual {v9, v10, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v10

    .line 177
    goto :goto_7

    .line 178
    :cond_a
    invoke-virtual {v9}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    invoke-static {v9}, Lkotlin/reflect/jvm/internal/UtilKt;->defaultPrimitiveValue(Ljava/lang/reflect/Type;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v10

    .line 189
    goto :goto_7

    .line 190
    :cond_b
    aget-object v10, p1, v7

    .line 191
    .line 192
    :goto_7
    aput-object v10, v8, v7

    .line 193
    .line 194
    add-int/lit8 v7, v7, 0x1

    .line 195
    .line 196
    goto :goto_5

    .line 197
    :cond_c
    move-object p1, v8

    .line 198
    :goto_8
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 199
    .line 200
    invoke-interface {p0, p1}, Lkotlin/reflect/jvm/internal/calls/Caller;->call([Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 205
    .line 206
    if-ne p0, p1, :cond_d

    .line 207
    .line 208
    goto :goto_9

    .line 209
    :cond_d
    if-eqz v2, :cond_f

    .line 210
    .line 211
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    invoke-virtual {v2, v5, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    if-nez p1, :cond_e

    .line 220
    .line 221
    goto :goto_9

    .line 222
    :cond_e
    return-object p1

    .line 223
    :cond_f
    :goto_9
    return-object p0
.end method

.method public getMember()Ljava/lang/reflect/Member;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TM;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->member:Ljava/lang/reflect/Member;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParameterTypes()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/reflect/Type;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 2
    .line 3
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/calls/Caller;->getParameterTypes()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getRealSlicesOfParameters(I)Lgy0/j;
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->slices:[Lgy0/j;

    .line 4
    .line 5
    array-length v1, v0

    .line 6
    if-ge p1, v1, :cond_0

    .line 7
    .line 8
    aget-object p0, v0, p1

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->slices:[Lgy0/j;

    .line 12
    .line 13
    array-length v0, p0

    .line 14
    const/4 v1, 0x1

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    new-instance p0, Lgy0/j;

    .line 18
    .line 19
    invoke-direct {p0, p1, p1, v1}, Lgy0/h;-><init>(III)V

    .line 20
    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    array-length v0, p0

    .line 24
    sub-int/2addr p1, v0

    .line 25
    invoke-static {p0}, Lmx0/n;->I([Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lgy0/j;

    .line 30
    .line 31
    iget p0, p0, Lgy0/h;->e:I

    .line 32
    .line 33
    add-int/2addr p0, v1

    .line 34
    add-int/2addr p0, p1

    .line 35
    new-instance p1, Lgy0/j;

    .line 36
    .line 37
    invoke-direct {p1, p0, p0, v1}, Lgy0/h;-><init>(III)V

    .line 38
    .line 39
    .line 40
    return-object p1
.end method

.method public getReturnType()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 2
    .line 3
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/calls/Caller;->getReturnType()Ljava/lang/reflect/Type;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public isBoundInstanceCallWithValueClasses()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/ValueClassAwareCaller;->caller:Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 2
    .line 3
    instance-of p0, p0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundInstance;

    .line 4
    .line 5
    return p0
.end method
