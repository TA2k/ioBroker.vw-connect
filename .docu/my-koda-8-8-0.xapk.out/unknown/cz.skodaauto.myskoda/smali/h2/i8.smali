.class public abstract Lh2/i8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgz0/e0;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lh2/i8;->a:Ll2/u2;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lh2/h8;Lk2/f0;)Le3/n0;
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, La8/r0;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    iget-object p0, p0, Lh2/h8;->b:Ls1/e;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_1
    sget-object p0, Le3/j0;->a:Le3/i0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_2
    iget-object p0, p0, Lh2/h8;->c:Ls1/e;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_3
    iget-object p0, p0, Lh2/h8;->d:Ls1/e;

    .line 24
    .line 25
    invoke-static {p0}, Lh2/i8;->c(Ls1/e;)Ls1/e;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_4
    iget-object v0, p0, Lh2/h8;->d:Ls1/e;

    .line 31
    .line 32
    sget-object v2, Lh2/g8;->i:Ls1/b;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    const/16 v5, 0x9

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    move-object v3, v2

    .line 39
    invoke-static/range {v0 .. v5}, Ls1/e;->b(Ls1/e;Ls1/a;Ls1/a;Ls1/a;Ls1/a;I)Ls1/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_5
    iget-object p0, p0, Lh2/h8;->f:Ls1/e;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_6
    iget-object v0, p0, Lh2/h8;->d:Ls1/e;

    .line 48
    .line 49
    sget-object v1, Lh2/g8;->i:Ls1/b;

    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    const/4 v5, 0x6

    .line 53
    const/4 v2, 0x0

    .line 54
    move-object v4, v1

    .line 55
    invoke-static/range {v0 .. v5}, Ls1/e;->b(Ls1/e;Ls1/a;Ls1/a;Ls1/a;Ls1/a;I)Ls1/e;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_7
    iget-object p0, p0, Lh2/h8;->d:Ls1/e;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_8
    sget-object p0, Ls1/f;->a:Ls1/e;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_9
    iget-object p0, p0, Lh2/h8;->a:Ls1/e;

    .line 67
    .line 68
    invoke-static {p0}, Lh2/i8;->c(Ls1/e;)Ls1/e;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_a
    iget-object p0, p0, Lh2/h8;->a:Ls1/e;

    .line 74
    .line 75
    return-object p0

    .line 76
    :pswitch_b
    iget-object p0, p0, Lh2/h8;->e:Ls1/e;

    .line 77
    .line 78
    invoke-static {p0}, Lh2/i8;->c(Ls1/e;)Ls1/e;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_c
    iget-object p0, p0, Lh2/h8;->g:Ls1/e;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_d
    iget-object p0, p0, Lh2/h8;->e:Ls1/e;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_e
    iget-object p0, p0, Lh2/h8;->h:Ls1/e;

    .line 90
    .line 91
    return-object p0

    .line 92
    nop

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_e
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
        :pswitch_0
    .end packed-switch
.end method

.method public static final b(Lk2/f0;Ll2/o;)Le3/n0;
    .locals 1

    .line 1
    sget-object v0, Lh2/i8;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p1, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lh2/h8;

    .line 10
    .line 11
    invoke-static {p1, p0}, Lh2/i8;->a(Lh2/h8;Lk2/f0;)Le3/n0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static c(Ls1/e;)Ls1/e;
    .locals 6

    .line 1
    sget-object v3, Lh2/g8;->i:Ls1/b;

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v5, 0x3

    .line 5
    const/4 v1, 0x0

    .line 6
    move-object v4, v3

    .line 7
    move-object v0, p0

    .line 8
    invoke-static/range {v0 .. v5}, Ls1/e;->b(Ls1/e;Ls1/a;Ls1/a;Ls1/a;Ls1/a;I)Ls1/e;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
