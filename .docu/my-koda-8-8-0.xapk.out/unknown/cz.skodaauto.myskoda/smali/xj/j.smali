.class public final synthetic Lxj/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzb/f;

.field public final synthetic f:Lzc/a;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lzb/f;Lzc/a;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lxj/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxj/j;->e:Lzb/f;

    iput-object p2, p0, Lxj/j;->f:Lzc/a;

    iput-object p3, p0, Lxj/j;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lzc/a;Lzb/f;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lxj/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxj/j;->f:Lzc/a;

    iput-object p2, p0, Lxj/j;->e:Lzb/f;

    iput-object p3, p0, Lxj/j;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lxj/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lzb/r0;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$ViewFlipper"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    check-cast p2, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    iget-object p1, p0, Lxj/j;->e:Lzb/f;

    .line 41
    .line 42
    iget-object p1, p1, Lzb/f;->b:Lay0/a;

    .line 43
    .line 44
    const/16 p3, 0x40

    .line 45
    .line 46
    iget-object v0, p0, Lxj/j;->f:Lzc/a;

    .line 47
    .line 48
    iget-object p0, p0, Lxj/j;->g:Lay0/k;

    .line 49
    .line 50
    invoke-static {p1, v0, p0, p2, p3}, Lxj/f;->c(Lay0/a;Lzc/a;Lay0/k;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_0
    const-string v0, "$this$ViewFlipper"

    .line 61
    .line 62
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    and-int/lit8 p1, p3, 0x11

    .line 66
    .line 67
    const/16 v0, 0x10

    .line 68
    .line 69
    const/4 v1, 0x1

    .line 70
    const/4 v2, 0x0

    .line 71
    if-eq p1, v0, :cond_2

    .line 72
    .line 73
    move p1, v1

    .line 74
    goto :goto_2

    .line 75
    :cond_2
    move p1, v2

    .line 76
    :goto_2
    and-int/2addr p3, v1

    .line 77
    check-cast p2, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_4

    .line 84
    .line 85
    iget-object p1, p0, Lxj/j;->f:Lzc/a;

    .line 86
    .line 87
    iget-boolean p3, p1, Lzc/a;->d:Z

    .line 88
    .line 89
    iget-object v0, p0, Lxj/j;->e:Lzb/f;

    .line 90
    .line 91
    iget-object p0, p0, Lxj/j;->g:Lay0/k;

    .line 92
    .line 93
    const/16 v1, 0x40

    .line 94
    .line 95
    if-eqz p3, :cond_3

    .line 96
    .line 97
    const p3, 0x2eb8ad35

    .line 98
    .line 99
    .line 100
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    iget-object p3, v0, Lzb/f;->b:Lay0/a;

    .line 104
    .line 105
    invoke-static {p3, p1, p0, p2, v1}, Lxj/f;->e(Lay0/a;Lzc/a;Lay0/k;Ll2/o;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p2, v2}, Ll2/t;->q(Z)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    const p3, 0x2ebac797

    .line 113
    .line 114
    .line 115
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 116
    .line 117
    .line 118
    iget-object p3, v0, Lzb/f;->b:Lay0/a;

    .line 119
    .line 120
    invoke-static {p3, p1, p0, p2, v1}, Lxj/f;->b(Lay0/a;Lzc/a;Lay0/k;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p2, v2}, Ll2/t;->q(Z)V

    .line 124
    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 128
    .line 129
    .line 130
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
