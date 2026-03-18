.class public final Ld21/a;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Ld21/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld21/a;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lap0/o;-><init>(Ld21/b;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final v(Ld21/b;Ljava/lang/String;)V
    .locals 2

    .line 1
    iget v0, p0, Ld21/a;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "msg"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    const-string v0, "Koin"

    .line 16
    .line 17
    if-eqz p1, :cond_4

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    if-eq p1, v1, :cond_3

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    if-eq p1, v1, :cond_2

    .line 24
    .line 25
    const/4 v1, 0x3

    .line 26
    if-eq p1, v1, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x4

    .line 29
    if-ne p1, p0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance p0, La8/r0;

    .line 33
    .line 34
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    new-instance p1, Lq61/c;

    .line 39
    .line 40
    const/16 v1, 0x12

    .line 41
    .line 42
    invoke-direct {p1, p2, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0, p0, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    new-instance p1, Lq61/c;

    .line 50
    .line 51
    const/16 v1, 0x12

    .line 52
    .line 53
    invoke-direct {p1, p2, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, p0, p1}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_3
    new-instance p1, Lq61/c;

    .line 61
    .line 62
    const/16 v1, 0x12

    .line 63
    .line 64
    invoke-direct {p1, p2, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_4
    new-instance p1, Lq61/c;

    .line 72
    .line 73
    const/16 v1, 0x12

    .line 74
    .line 75
    invoke-direct {p1, p2, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v0, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 79
    .line 80
    .line 81
    :goto_0
    return-void

    .line 82
    :pswitch_0
    const-string p0, "msg"

    .line 83
    .line 84
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
