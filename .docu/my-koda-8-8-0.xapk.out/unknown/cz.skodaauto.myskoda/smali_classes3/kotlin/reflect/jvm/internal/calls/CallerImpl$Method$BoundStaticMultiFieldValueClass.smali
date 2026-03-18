.class public final Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;
.super Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/calls/BoundCaller;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "BoundStaticMultiFieldValueClass"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0011\n\u0002\u0010\u0000\n\u0002\u0008\t\n\u0002\u0010\u0008\n\u0002\u0008\u0003\u0018\u00002\u00020\u00012\u00020\u0002B\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u0012\u000e\u0010\u0005\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00070\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u001b\u0010\r\u001a\u0004\u0018\u00010\u00072\n\u0010\u000e\u001a\u0006\u0012\u0002\u0008\u00030\u0006H\u0016\u00a2\u0006\u0002\u0010\u000fR\u001e\u0010\u0005\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00070\u0006X\u0080\u0004\u00a2\u0006\n\n\u0002\u0010\u000c\u001a\u0004\u0008\n\u0010\u000bR\u0011\u0010\u0010\u001a\u00020\u00118F\u00a2\u0006\u0006\u001a\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0014"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;",
        "Lkotlin/reflect/jvm/internal/calls/BoundCaller;",
        "Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;",
        "method",
        "Ljava/lang/reflect/Method;",
        "boundReceiverComponents",
        "",
        "",
        "<init>",
        "(Ljava/lang/reflect/Method;[Ljava/lang/Object;)V",
        "getBoundReceiverComponents$kotlin_reflection",
        "()[Ljava/lang/Object;",
        "[Ljava/lang/Object;",
        "call",
        "args",
        "([Ljava/lang/Object;)Ljava/lang/Object;",
        "receiverComponentsCount",
        "",
        "getReceiverComponentsCount",
        "()I",
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
.field private final boundReceiverComponents:[Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Method;[Ljava/lang/Object;)V
    .locals 6

    .line 1
    const-string v0, "method"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "boundReceiverComponents"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/reflect/Method;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "getGenericParameterTypes(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    array-length v1, p2

    .line 21
    const-string v2, " is less than zero."

    .line 22
    .line 23
    const-string v3, "Requested element count "

    .line 24
    .line 25
    if-ltz v1, :cond_6

    .line 26
    .line 27
    array-length v4, v0

    .line 28
    sub-int/2addr v4, v1

    .line 29
    const/4 v1, 0x0

    .line 30
    if-gez v4, :cond_0

    .line 31
    .line 32
    move v4, v1

    .line 33
    :cond_0
    if-ltz v4, :cond_5

    .line 34
    .line 35
    if-nez v4, :cond_1

    .line 36
    .line 37
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    array-length v2, v0

    .line 41
    if-lt v4, v2, :cond_2

    .line 42
    .line 43
    invoke-static {v0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    goto :goto_1

    .line 48
    :cond_2
    const/4 v3, 0x1

    .line 49
    if-ne v4, v3, :cond_3

    .line 50
    .line 51
    sub-int/2addr v2, v3

    .line 52
    aget-object v0, v0, v2

    .line 53
    .line 54
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    goto :goto_1

    .line 59
    :cond_3
    new-instance v3, Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 62
    .line 63
    .line 64
    sub-int v4, v2, v4

    .line 65
    .line 66
    :goto_0
    if-ge v4, v2, :cond_4

    .line 67
    .line 68
    aget-object v5, v0, v4

    .line 69
    .line 70
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    add-int/lit8 v4, v4, 0x1

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_4
    move-object v0, v3

    .line 77
    :goto_1
    check-cast v0, Ljava/util/Collection;

    .line 78
    .line 79
    new-array v2, v1, [Ljava/lang/reflect/Type;

    .line 80
    .line 81
    invoke-interface {v0, v2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, [Ljava/lang/reflect/Type;

    .line 86
    .line 87
    const/4 v2, 0x0

    .line 88
    invoke-direct {p0, p1, v1, v0, v2}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;-><init>(Ljava/lang/reflect/Method;Z[Ljava/lang/reflect/Type;Lkotlin/jvm/internal/g;)V

    .line 89
    .line 90
    .line 91
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->boundReceiverComponents:[Ljava/lang/Object;

    .line 92
    .line 93
    return-void

    .line 94
    :cond_5
    invoke-static {v3, v4, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p1

    .line 108
    :cond_6
    invoke-static {v3, v1, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p1
.end method


# virtual methods
.method public call([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "args"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/calls/CallerImpl;->checkArguments([Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ld01/x;

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    invoke-direct {v0, v1}, Ld01/x;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->boundReceiverComponents:[Ljava/lang/Object;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ld01/x;->g(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ld01/x;->g(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, v0, Ld01/x;->b:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    new-array v0, v0, [Ljava/lang/Object;

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    const/4 v0, 0x0

    .line 36
    invoke-virtual {p0, v0, p1}, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method;->callMethod(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method public final getBoundReceiverComponents$kotlin_reflection()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->boundReceiverComponents:[Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getReceiverComponentsCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/CallerImpl$Method$BoundStaticMultiFieldValueClass;->boundReceiverComponents:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method
