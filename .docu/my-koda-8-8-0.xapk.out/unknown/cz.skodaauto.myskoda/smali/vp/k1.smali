.class public final Lvp/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/String;

.field public final synthetic c:Ljava/lang/String;

.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lvp/m1;


# direct methods
.method public synthetic constructor <init>(Lvp/m1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p5, p0, Lvp/k1;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lvp/k1;->b:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Lvp/k1;->c:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p4, p0, Lvp/k1;->d:Ljava/lang/String;

    .line 8
    .line 9
    iput-object p1, p0, Lvp/k1;->e:Lvp/m1;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lvp/k1;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/k1;->e:Lvp/m1;

    .line 7
    .line 8
    iget-object v1, v0, Lvp/m1;->c:Lvp/z3;

    .line 9
    .line 10
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 11
    .line 12
    .line 13
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 16
    .line 17
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lvp/k1;->c:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v2, p0, Lvp/k1;->d:Ljava/lang/String;

    .line 23
    .line 24
    iget-object p0, p0, Lvp/k1;->b:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v0, p0, v1, v2}, Lvp/n;->a1(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object v0, p0, Lvp/k1;->e:Lvp/m1;

    .line 32
    .line 33
    iget-object v1, v0, Lvp/m1;->c:Lvp/z3;

    .line 34
    .line 35
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 36
    .line 37
    .line 38
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 39
    .line 40
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 41
    .line 42
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lvp/k1;->c:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v2, p0, Lvp/k1;->d:Ljava/lang/String;

    .line 48
    .line 49
    iget-object p0, p0, Lvp/k1;->b:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0, p0, v1, v2}, Lvp/n;->a1(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object v0, p0, Lvp/k1;->e:Lvp/m1;

    .line 57
    .line 58
    iget-object v1, v0, Lvp/m1;->c:Lvp/z3;

    .line 59
    .line 60
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 61
    .line 62
    .line 63
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 64
    .line 65
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 66
    .line 67
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Lvp/k1;->c:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v2, p0, Lvp/k1;->d:Ljava/lang/String;

    .line 73
    .line 74
    iget-object p0, p0, Lvp/k1;->b:Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {v0, p0, v1, v2}, Lvp/n;->W0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_2
    iget-object v0, p0, Lvp/k1;->e:Lvp/m1;

    .line 82
    .line 83
    iget-object v1, v0, Lvp/m1;->c:Lvp/z3;

    .line 84
    .line 85
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 86
    .line 87
    .line 88
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 89
    .line 90
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 91
    .line 92
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 93
    .line 94
    .line 95
    iget-object v1, p0, Lvp/k1;->c:Ljava/lang/String;

    .line 96
    .line 97
    iget-object v2, p0, Lvp/k1;->d:Ljava/lang/String;

    .line 98
    .line 99
    iget-object p0, p0, Lvp/k1;->b:Ljava/lang/String;

    .line 100
    .line 101
    invoke-virtual {v0, p0, v1, v2}, Lvp/n;->W0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
