.class public Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver;
.super Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/AbstractReceiverValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ImplicitReceiver;


# instance fields
.field private final descriptor:Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 8

    .line 1
    const/4 v0, 0x2

    .line 2
    if-eq p0, v0, :cond_0

    .line 3
    .line 4
    const-string v1, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const-string v1, "@NotNull method %s.%s must not return null"

    .line 8
    .line 9
    :goto_0
    const/4 v2, 0x3

    .line 10
    if-eq p0, v0, :cond_1

    .line 11
    .line 12
    move v3, v2

    .line 13
    goto :goto_1

    .line 14
    :cond_1
    move v3, v0

    .line 15
    :goto_1
    new-array v3, v3, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v4, "kotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver"

    .line 18
    .line 19
    const/4 v5, 0x1

    .line 20
    const/4 v6, 0x0

    .line 21
    if-eq p0, v5, :cond_4

    .line 22
    .line 23
    if-eq p0, v0, :cond_3

    .line 24
    .line 25
    if-eq p0, v2, :cond_2

    .line 26
    .line 27
    const-string v7, "callableDescriptor"

    .line 28
    .line 29
    aput-object v7, v3, v6

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    const-string v7, "newType"

    .line 33
    .line 34
    aput-object v7, v3, v6

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_3
    aput-object v4, v3, v6

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_4
    const-string v7, "receiverType"

    .line 41
    .line 42
    aput-object v7, v3, v6

    .line 43
    .line 44
    :goto_2
    if-eq p0, v0, :cond_5

    .line 45
    .line 46
    aput-object v4, v3, v5

    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_5
    const-string v4, "getDeclarationDescriptor"

    .line 50
    .line 51
    aput-object v4, v3, v5

    .line 52
    .line 53
    :goto_3
    if-eq p0, v0, :cond_7

    .line 54
    .line 55
    if-eq p0, v2, :cond_6

    .line 56
    .line 57
    const-string v2, "<init>"

    .line 58
    .line 59
    aput-object v2, v3, v0

    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_6
    const-string v2, "replaceType"

    .line 63
    .line 64
    aput-object v2, v3, v0

    .line 65
    .line 66
    :cond_7
    :goto_4
    invoke-static {v1, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-eq p0, v0, :cond_8

    .line 71
    .line 72
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    goto :goto_5

    .line 78
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    :goto_5
    throw p0
.end method

.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ReceiverValue;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p2, :cond_1

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver;->$$$reportNull$$$0(I)V

    .line 11
    .line 12
    .line 13
    :cond_1
    invoke-direct {p0, p2, p3}, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/AbstractReceiverValue;-><init>(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ReceiverValue;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver;->descriptor:Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/AbstractReceiverValue;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ": Ext {"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/resolve/scopes/receivers/ExtensionReceiver;->descriptor:Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "}"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
