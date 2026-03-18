.class public abstract Lkp/y8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    iput v0, p0, Lkp/y8;->a:I

    .line 3
    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static final a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V
    .locals 3

    .line 1
    const-string v0, "caller"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "level"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lkp/x8;->a:Lrb0/a;

    .line 12
    .line 13
    if-eqz v0, :cond_5

    .line 14
    .line 15
    new-instance v1, Lgi/c;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p0, v1, Lgi/c;->a:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const-string p1, "MULTI."

    .line 27
    .line 28
    invoke-static {p1, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    new-instance p1, Ld90/w;

    .line 33
    .line 34
    const/16 v2, 0x14

    .line 35
    .line 36
    invoke-direct {p1, v2, p4, v1}, Ld90/w;-><init>(ILay0/k;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    if-eqz p2, :cond_4

    .line 44
    .line 45
    const/4 p4, 0x1

    .line 46
    if-eq p2, p4, :cond_3

    .line 47
    .line 48
    const/4 p4, 0x2

    .line 49
    if-eq p2, p4, :cond_2

    .line 50
    .line 51
    const/4 p4, 0x3

    .line 52
    if-eq p2, p4, :cond_1

    .line 53
    .line 54
    const/4 p4, 0x4

    .line 55
    if-ne p2, p4, :cond_0

    .line 56
    .line 57
    new-instance p2, Lvo0/c;

    .line 58
    .line 59
    const/4 p4, 0x0

    .line 60
    invoke-direct {p2, p1, v0, p3, p4}, Lvo0/c;-><init>(Lay0/a;Lrb0/a;Ljava/lang/Throwable;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {p0, v0, p2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_0
    new-instance p0, La8/r0;

    .line 68
    .line 69
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_1
    new-instance p2, Lvo0/c;

    .line 74
    .line 75
    const/4 p4, 0x1

    .line 76
    invoke-direct {p2, p1, v0, p3, p4}, Lvo0/c;-><init>(Lay0/a;Lrb0/a;Ljava/lang/Throwable;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {p0, v0, p2}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :cond_2
    new-instance p2, Lvo0/c;

    .line 84
    .line 85
    const/4 p4, 0x2

    .line 86
    invoke-direct {p2, p1, v0, p3, p4}, Lvo0/c;-><init>(Lay0/a;Lrb0/a;Ljava/lang/Throwable;I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0, v0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_3
    new-instance p2, Lvo0/c;

    .line 94
    .line 95
    const/4 p4, 0x3

    .line 96
    invoke-direct {p2, p1, v0, p3, p4}, Lvo0/c;-><init>(Lay0/a;Lrb0/a;Ljava/lang/Throwable;I)V

    .line 97
    .line 98
    .line 99
    invoke-static {p0, v0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :cond_4
    new-instance p2, Lvo0/c;

    .line 104
    .line 105
    const/4 p4, 0x4

    .line 106
    invoke-direct {p2, p1, v0, p3, p4}, Lvo0/c;-><init>(Lay0/a;Lrb0/a;Ljava/lang/Throwable;I)V

    .line 107
    .line 108
    .line 109
    invoke-static {p0, v0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 110
    .line 111
    .line 112
    :cond_5
    return-void
.end method

.method public static synthetic b(Ljava/lang/String;Lgi/b;Ljava/lang/Throwable;Lay0/k;I)V
    .locals 2

    .line 1
    sget-object v0, Lgi/a;->d:Lgi/a;

    .line 2
    .line 3
    and-int/lit8 v1, p4, 0x4

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    sget-object p1, Lgi/b;->e:Lgi/b;

    .line 8
    .line 9
    :cond_0
    and-int/lit8 p4, p4, 0x8

    .line 10
    .line 11
    if-eqz p4, :cond_1

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    :cond_1
    invoke-static {p0, v0, p1, p2, p3}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lkp/y8;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-virtual {p0}, Lkp/y8;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lkp/y8;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method
