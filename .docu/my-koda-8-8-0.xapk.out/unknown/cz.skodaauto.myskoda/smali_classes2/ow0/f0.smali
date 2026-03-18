.class public final Low0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# annotations
.annotation runtime Lqz0/g;
    with = Low0/g0;
.end annotation


# static fields
.field public static final Companion:Low0/e0;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:I

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Low0/b0;

.field public final j:Low0/b0;

.field public final k:Llx0/q;

.field public final l:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Low0/e0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Low0/f0;->Companion:Low0/e0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Low0/b0;Ljava/lang/String;ILjava/util/ArrayList;Low0/x;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "host"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "parameters"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p5, "fragment"

    .line 12
    .line 13
    invoke-static {p6, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p2, p0, Low0/f0;->d:Ljava/lang/String;

    .line 20
    .line 21
    iput p3, p0, Low0/f0;->e:I

    .line 22
    .line 23
    iput-object p7, p0, Low0/f0;->f:Ljava/lang/String;

    .line 24
    .line 25
    iput-object p8, p0, Low0/f0;->g:Ljava/lang/String;

    .line 26
    .line 27
    iput-object p9, p0, Low0/f0;->h:Ljava/lang/String;

    .line 28
    .line 29
    if-ltz p3, :cond_1

    .line 30
    .line 31
    const/high16 p2, 0x10000

    .line 32
    .line 33
    if-ge p3, p2, :cond_1

    .line 34
    .line 35
    new-instance p2, Low0/c0;

    .line 36
    .line 37
    const/4 p3, 0x0

    .line 38
    invoke-direct {p2, p4, p3}, Low0/c0;-><init>(Ljava/util/ArrayList;I)V

    .line 39
    .line 40
    .line 41
    invoke-static {p2}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 42
    .line 43
    .line 44
    iput-object p1, p0, Low0/f0;->i:Low0/b0;

    .line 45
    .line 46
    if-nez p1, :cond_0

    .line 47
    .line 48
    sget-object p1, Low0/b0;->f:Low0/b0;

    .line 49
    .line 50
    :cond_0
    iput-object p1, p0, Low0/f0;->j:Low0/b0;

    .line 51
    .line 52
    new-instance p1, Lo51/c;

    .line 53
    .line 54
    const/4 p2, 0x2

    .line 55
    invoke-direct {p1, p2, p4, p0}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 59
    .line 60
    .line 61
    new-instance p1, Low0/d0;

    .line 62
    .line 63
    const/4 p2, 0x0

    .line 64
    invoke-direct {p1, p0, p2}, Low0/d0;-><init>(Low0/f0;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 68
    .line 69
    .line 70
    new-instance p1, Low0/d0;

    .line 71
    .line 72
    const/4 p2, 0x1

    .line 73
    invoke-direct {p1, p0, p2}, Low0/d0;-><init>(Low0/f0;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 77
    .line 78
    .line 79
    new-instance p1, Low0/d0;

    .line 80
    .line 81
    const/4 p2, 0x2

    .line 82
    invoke-direct {p1, p0, p2}, Low0/d0;-><init>(Low0/f0;I)V

    .line 83
    .line 84
    .line 85
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Low0/f0;->k:Llx0/q;

    .line 90
    .line 91
    new-instance p1, Low0/d0;

    .line 92
    .line 93
    const/4 p2, 0x3

    .line 94
    invoke-direct {p1, p0, p2}, Low0/d0;-><init>(Low0/f0;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    iput-object p1, p0, Low0/f0;->l:Llx0/q;

    .line 102
    .line 103
    new-instance p1, Low0/d0;

    .line 104
    .line 105
    const/4 p2, 0x4

    .line 106
    invoke-direct {p1, p0, p2}, Low0/d0;-><init>(Low0/f0;I)V

    .line 107
    .line 108
    .line 109
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :cond_1
    const-string p0, "Port must be between 0 and 65535, or 0 if not set. Provided: "

    .line 114
    .line 115
    invoke-static {p3, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 120
    .line 121
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p1
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    if-eqz p1, :cond_2

    .line 6
    .line 7
    const-class v0, Low0/f0;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    check-cast p1, Low0/f0;

    .line 17
    .line 18
    iget-object p0, p0, Low0/f0;->h:Ljava/lang/String;

    .line 19
    .line 20
    iget-object p1, p1, Low0/f0;->h:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Low0/f0;->h:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Low0/f0;->h:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
