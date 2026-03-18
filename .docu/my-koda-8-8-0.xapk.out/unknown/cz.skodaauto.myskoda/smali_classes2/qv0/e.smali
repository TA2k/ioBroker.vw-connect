.class public final synthetic Lqv0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Z

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IIILjava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lqv0/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lqv0/e;->e:I

    iput-object p4, p0, Lqv0/e;->f:Ljava/lang/Object;

    iput-boolean p6, p0, Lqv0/e;->g:Z

    iput-object p5, p0, Lqv0/e;->j:Ljava/lang/Object;

    iput p2, p0, Lqv0/e;->h:I

    iput p3, p0, Lqv0/e;->i:I

    return-void
.end method

.method public synthetic constructor <init>(ILay0/a;ZLjava/lang/String;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lqv0/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lqv0/e;->e:I

    iput-object p2, p0, Lqv0/e;->j:Ljava/lang/Object;

    iput-boolean p3, p0, Lqv0/e;->g:Z

    iput-object p4, p0, Lqv0/e;->f:Ljava/lang/Object;

    iput p5, p0, Lqv0/e;->h:I

    iput p6, p0, Lqv0/e;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lkd/a;Lay0/k;IZII)V
    .locals 1

    .line 3
    const/4 v0, 0x2

    iput v0, p0, Lqv0/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lqv0/e;->j:Ljava/lang/Object;

    iput-object p2, p0, Lqv0/e;->f:Ljava/lang/Object;

    iput p3, p0, Lqv0/e;->e:I

    iput-boolean p4, p0, Lqv0/e;->g:Z

    iput p5, p0, Lqv0/e;->h:I

    iput p6, p0, Lqv0/e;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lqv0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lqv0/e;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lkd/a;

    .line 10
    .line 11
    iget-object v0, p0, Lqv0/e;->f:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Lay0/k;

    .line 15
    .line 16
    move-object v5, p1

    .line 17
    check-cast v5, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget p1, p0, Lqv0/e;->h:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    iget v3, p0, Lqv0/e;->e:I

    .line 33
    .line 34
    iget-boolean v4, p0, Lqv0/e;->g:Z

    .line 35
    .line 36
    iget v7, p0, Lqv0/e;->i:I

    .line 37
    .line 38
    invoke-static/range {v1 .. v7}, Lyj/a;->i(Lkd/a;Lay0/k;IZLl2/o;II)V

    .line 39
    .line 40
    .line 41
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_0
    iget-object v0, p0, Lqv0/e;->f:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v2, v0

    .line 47
    check-cast v2, Ljava/lang/String;

    .line 48
    .line 49
    iget-object v0, p0, Lqv0/e;->j:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v4, v0

    .line 52
    check-cast v4, Ljava/lang/String;

    .line 53
    .line 54
    move-object v5, p1

    .line 55
    check-cast v5, Ll2/o;

    .line 56
    .line 57
    check-cast p2, Ljava/lang/Integer;

    .line 58
    .line 59
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    iget p1, p0, Lqv0/e;->h:I

    .line 63
    .line 64
    or-int/lit8 p1, p1, 0x1

    .line 65
    .line 66
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    iget v1, p0, Lqv0/e;->e:I

    .line 71
    .line 72
    iget-boolean v3, p0, Lqv0/e;->g:Z

    .line 73
    .line 74
    iget v7, p0, Lqv0/e;->i:I

    .line 75
    .line 76
    invoke-static/range {v1 .. v7}, Lyc0/a;->a(ILjava/lang/String;ZLjava/lang/String;Ll2/o;II)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_1
    iget-object v0, p0, Lqv0/e;->j:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v2, v0

    .line 83
    check-cast v2, Lay0/a;

    .line 84
    .line 85
    iget-object v0, p0, Lqv0/e;->f:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v4, v0

    .line 88
    check-cast v4, Ljava/lang/String;

    .line 89
    .line 90
    move-object v5, p1

    .line 91
    check-cast v5, Ll2/o;

    .line 92
    .line 93
    check-cast p2, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    iget p1, p0, Lqv0/e;->h:I

    .line 99
    .line 100
    or-int/lit8 p1, p1, 0x1

    .line 101
    .line 102
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 103
    .line 104
    .line 105
    move-result v6

    .line 106
    iget v1, p0, Lqv0/e;->e:I

    .line 107
    .line 108
    iget-boolean v3, p0, Lqv0/e;->g:Z

    .line 109
    .line 110
    iget v7, p0, Lqv0/e;->i:I

    .line 111
    .line 112
    invoke-static/range {v1 .. v7}, Lqv0/a;->b(ILay0/a;ZLjava/lang/String;Ll2/o;II)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
