.class public final Lkotlin/reflect/jvm/internal/impl/km/KmProperty;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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
.field private final _hasGetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

.field private final _hasSetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

.field private final annotations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation
.end field

.field private final backingFieldAnnotations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation
.end field

.field private final contextParameters:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;",
            ">;"
        }
    .end annotation
.end field

.field private final contextReceiverTypes:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmType;",
            ">;"
        }
    .end annotation
.end field

.field private final delegateFieldAnnotations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation
.end field

.field private final extensionReceiverParameterAnnotations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation
.end field

.field private final extensions:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmPropertyExtension;",
            ">;"
        }
    .end annotation
.end field

.field private flags:I

.field private final getter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

.field private name:Ljava/lang/String;

.field private receiverParameterType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

.field public returnType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

.field private setter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

.field private setterParameter:Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

.field private final typeParameters:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;",
            ">;"
        }
    .end annotation
.end field

.field private final versionRequirements:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lkotlin/jvm/internal/r;

    .line 2
    .line 3
    const-class v1, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;

    .line 4
    .line 5
    const-string v2, "_hasSetter"

    .line 6
    .line 7
    const-string v3, "get_hasSetter()Z"

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
    const-string v3, "_hasGetter"

    .line 20
    .line 21
    const-string v5, "get_hasGetter()Z"

    .line 22
    .line 23
    invoke-static {v1, v3, v5, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const/4 v2, 0x2

    .line 28
    new-array v2, v2, [Lhy0/z;

    .line 29
    .line 30
    aput-object v0, v2, v4

    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    aput-object v1, v2, v0

    .line 34
    .line 35
    sput-object v2, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->$$delegatedProperties:[Lhy0/z;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(ILjava/lang/String;II)V
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->flags:I

    .line 10
    .line 11
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->name:Ljava/lang/String;

    .line 12
    .line 13
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 14
    .line 15
    sget-object p2, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->HAS_SETTER:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 16
    .line 17
    const-string v0, "HAS_SETTER"

    .line 18
    .line 19
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-direct {p1, p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagDelegatesImplKt;->propertyBooleanFlag(Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;)Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->_hasSetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 30
    .line 31
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;

    .line 32
    .line 33
    sget-object p2, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->HAS_GETTER:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 34
    .line 35
    const-string v0, "HAS_GETTER"

    .line 36
    .line 37
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-direct {p1, p2}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;)V

    .line 41
    .line 42
    .line 43
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/FlagDelegatesImplKt;->propertyBooleanFlag(Lkotlin/reflect/jvm/internal/impl/km/internal/FlagImpl;)Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->_hasGetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 48
    .line 49
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 50
    .line 51
    invoke-direct {p1, p3}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;-><init>(I)V

    .line 52
    .line 53
    .line 54
    const/4 p2, 0x1

    .line 55
    invoke-direct {p0, p2}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->set_hasGetter(Z)V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 59
    .line 60
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->get_hasSetter()Z

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    if-eqz p1, :cond_0

    .line 65
    .line 66
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 67
    .line 68
    invoke-direct {p1, p4}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;-><init>(I)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    const/4 p1, 0x0

    .line 73
    :goto_0
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->setter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 74
    .line 75
    new-instance p1, Ljava/util/ArrayList;

    .line 76
    .line 77
    const/4 p2, 0x0

    .line 78
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 79
    .line 80
    .line 81
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->typeParameters:Ljava/util/List;

    .line 82
    .line 83
    new-instance p1, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 86
    .line 87
    .line 88
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->extensionReceiverParameterAnnotations:Ljava/util/List;

    .line 89
    .line 90
    new-instance p1, Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 93
    .line 94
    .line 95
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->contextReceiverTypes:Ljava/util/List;

    .line 96
    .line 97
    new-instance p1, Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->contextParameters:Ljava/util/List;

    .line 103
    .line 104
    new-instance p1, Ljava/util/ArrayList;

    .line 105
    .line 106
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 107
    .line 108
    .line 109
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->versionRequirements:Ljava/util/List;

    .line 110
    .line 111
    new-instance p1, Ljava/util/ArrayList;

    .line 112
    .line 113
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 114
    .line 115
    .line 116
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->annotations:Ljava/util/List;

    .line 117
    .line 118
    new-instance p1, Ljava/util/ArrayList;

    .line 119
    .line 120
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 121
    .line 122
    .line 123
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->backingFieldAnnotations:Ljava/util/List;

    .line 124
    .line 125
    new-instance p1, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 128
    .line 129
    .line 130
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->delegateFieldAnnotations:Ljava/util/List;

    .line 131
    .line 132
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->Companion:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;

    .line 133
    .line 134
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions$Companion;->getINSTANCES$kotlin_metadata()Ljava/util/List;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    check-cast p1, Ljava/lang/Iterable;

    .line 139
    .line 140
    new-instance p2, Ljava/util/ArrayList;

    .line 141
    .line 142
    const/16 p3, 0xa

    .line 143
    .line 144
    invoke-static {p1, p3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 145
    .line 146
    .line 147
    move-result p3

    .line 148
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 149
    .line 150
    .line 151
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 156
    .line 157
    .line 158
    move-result p3

    .line 159
    if-eqz p3, :cond_1

    .line 160
    .line 161
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    check-cast p3, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 166
    .line 167
    invoke-interface {p3}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->createPropertyExtension()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmPropertyExtension;

    .line 168
    .line 169
    .line 170
    move-result-object p3

    .line 171
    invoke-interface {p2, p3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    goto :goto_1

    .line 175
    :cond_1
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->extensions:Ljava/util/List;

    .line 176
    .line 177
    return-void
.end method

.method private final get_hasSetter()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->_hasSetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-virtual {v0, p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->getValue(Ljava/lang/Object;Lhy0/z;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method private final set_hasGetter(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->_hasGetter$delegate:Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;

    .line 2
    .line 3
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->$$delegatedProperties:[Lhy0/z;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    aget-object v1, v1, v2

    .line 7
    .line 8
    invoke-virtual {v0, p0, v1, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/BooleanFlagDelegate;->setValue(Ljava/lang/Object;Lhy0/z;Z)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final getAnnotations()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->annotations:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getBackingFieldAnnotations()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->backingFieldAnnotations:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getContextParameters()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->contextParameters:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDelegateFieldAnnotations()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->delegateFieldAnnotations:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getExtensionReceiverParameterAnnotations()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotation;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->extensionReceiverParameterAnnotations:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getExtensions$kotlin_metadata()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmPropertyExtension;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->extensions:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFlags$kotlin_metadata()I
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->flags:I

    .line 2
    .line 3
    return p0
.end method

.method public final getGetter()Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getReceiverParameterType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->receiverParameterType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getReturnType()Lkotlin/reflect/jvm/internal/impl/km/KmType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->returnType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "returnType"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final getSetter()Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->setter:Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSetterParameter()Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->setterParameter:Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTypeParameters()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->typeParameters:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVersionRequirements()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->versionRequirements:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setFlags$kotlin_metadata(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->flags:I

    .line 2
    .line 3
    return-void
.end method

.method public final setReceiverParameterType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->receiverParameterType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 2
    .line 3
    return-void
.end method

.method public final setReturnType(Lkotlin/reflect/jvm/internal/impl/km/KmType;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->returnType:Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 7
    .line 8
    return-void
.end method

.method public final setSetterParameter(Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->setterParameter:Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

    .line 2
    .line 3
    return-void
.end method
