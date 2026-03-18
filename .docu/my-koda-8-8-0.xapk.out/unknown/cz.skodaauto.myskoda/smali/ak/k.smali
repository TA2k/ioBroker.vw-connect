.class public final synthetic Lak/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lak/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lak/k;->e:Ljava/lang/String;

    iput-object p2, p0, Lak/k;->f:Ljava/lang/String;

    iput-object p3, p0, Lak/k;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;II)V
    .locals 0

    .line 2
    iput p5, p0, Lak/k;->d:I

    iput-object p1, p0, Lak/k;->e:Ljava/lang/String;

    iput-object p2, p0, Lak/k;->f:Ljava/lang/String;

    iput-object p3, p0, Lak/k;->g:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lak/k;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x181

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Lak/k;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v1, p0, Lak/k;->f:Ljava/lang/String;

    .line 22
    .line 23
    iget-object p0, p0, Lak/k;->g:Lay0/a;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Lwk/a;->q(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/4 p2, 0x1

    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget-object v0, p0, Lak/k;->e:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v1, p0, Lak/k;->f:Ljava/lang/String;

    .line 42
    .line 43
    iget-object p0, p0, Lak/k;->g:Lay0/a;

    .line 44
    .line 45
    invoke-static {v0, v1, p0, p1, p2}, Llp/l1;->a(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    and-int/lit8 v0, p2, 0x3

    .line 54
    .line 55
    const/4 v1, 0x2

    .line 56
    const/4 v2, 0x0

    .line 57
    const/4 v3, 0x1

    .line 58
    if-eq v0, v1, :cond_0

    .line 59
    .line 60
    move v0, v3

    .line 61
    goto :goto_1

    .line 62
    :cond_0
    move v0, v2

    .line 63
    :goto_1
    and-int/2addr p2, v3

    .line 64
    check-cast p1, Ll2/t;

    .line 65
    .line 66
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_1

    .line 71
    .line 72
    iget-object p2, p0, Lak/k;->e:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v0, p0, Lak/k;->f:Ljava/lang/String;

    .line 75
    .line 76
    iget-object p0, p0, Lak/k;->g:Lay0/a;

    .line 77
    .line 78
    invoke-static {p2, v0, p0, p1, v2}, Llp/l1;->a(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 83
    .line 84
    .line 85
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    const/4 p2, 0x1

    .line 92
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    iget-object v0, p0, Lak/k;->e:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v1, p0, Lak/k;->f:Ljava/lang/String;

    .line 99
    .line 100
    iget-object p0, p0, Lak/k;->g:Lay0/a;

    .line 101
    .line 102
    invoke-static {v0, v1, p0, p1, p2}, Ljp/la;->a(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    const/4 p2, 0x1

    .line 110
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    iget-object v0, p0, Lak/k;->e:Ljava/lang/String;

    .line 115
    .line 116
    iget-object v1, p0, Lak/k;->f:Ljava/lang/String;

    .line 117
    .line 118
    iget-object p0, p0, Lak/k;->g:Lay0/a;

    .line 119
    .line 120
    invoke-static {v0, v1, p0, p1, p2}, Lak/a;->i(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    goto :goto_0

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
