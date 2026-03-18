.class public final synthetic Lh2/v2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/o3;


# direct methods
.method public synthetic constructor <init>(Lh2/o3;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/v2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/v2;->e:Lh2/o3;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lh2/v2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Long;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-object p0, p0, Lh2/v2;->e:Lh2/o3;

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1}, Lh2/s;->b(J)V

    .line 15
    .line 16
    .line 17
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    check-cast p1, Ljava/lang/Long;

    .line 21
    .line 22
    iget-object p0, p0, Lh2/v2;->e:Lh2/o3;

    .line 23
    .line 24
    iget-object v0, p0, Lh2/o3;->f:Ll2/j1;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    iget-object v2, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v2, Li2/b0;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 34
    .line 35
    .line 36
    move-result-wide v3

    .line 37
    invoke-virtual {v2, v3, v4}, Li2/b0;->a(J)Li2/y;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iget-object p0, p0, Lh2/s;->a:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lgy0/j;

    .line 44
    .line 45
    iget v2, p1, Li2/y;->d:I

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Lgy0/j;->i(I)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-eqz p0, :cond_0

    .line 52
    .line 53
    move-object v1, p1

    .line 54
    :cond_0
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    return-object p0

    .line 64
    :pswitch_1
    check-cast p1, Lh2/o4;

    .line 65
    .line 66
    iget p1, p1, Lh2/o4;->a:I

    .line 67
    .line 68
    iget-object p0, p0, Lh2/v2;->e:Lh2/o3;

    .line 69
    .line 70
    invoke-virtual {p0}, Lh2/o3;->g()Ljava/lang/Long;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 77
    .line 78
    .line 79
    move-result-wide v0

    .line 80
    iget-object v2, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v2, Li2/b0;

    .line 83
    .line 84
    invoke-virtual {v2, v0, v1}, Li2/b0;->b(J)Li2/c0;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    iget-wide v0, v0, Li2/c0;->e:J

    .line 89
    .line 90
    invoke-virtual {p0, v0, v1}, Lh2/s;->b(J)V

    .line 91
    .line 92
    .line 93
    :cond_2
    iget-object p0, p0, Lh2/o3;->g:Ll2/j1;

    .line 94
    .line 95
    new-instance v0, Lh2/o4;

    .line 96
    .line 97
    invoke-direct {v0, p1}, Lh2/o4;-><init>(I)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
