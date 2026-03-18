.class public final synthetic Lgr0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:I

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;ZIII)V
    .locals 0

    .line 1
    iput p6, p0, Lgr0/b;->d:I

    iput-object p1, p0, Lgr0/b;->e:Ljava/lang/String;

    iput-object p2, p0, Lgr0/b;->f:Lx2/s;

    iput-boolean p3, p0, Lgr0/b;->g:Z

    iput p4, p0, Lgr0/b;->h:I

    iput p5, p0, Lgr0/b;->i:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ZLx2/s;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lgr0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lgr0/b;->e:Ljava/lang/String;

    iput-boolean p2, p0, Lgr0/b;->g:Z

    iput-object p3, p0, Lgr0/b;->f:Lx2/s;

    iput p4, p0, Lgr0/b;->h:I

    iput p5, p0, Lgr0/b;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lgr0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v4, p1

    .line 7
    check-cast v4, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lgr0/b;->h:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget v2, p0, Lgr0/b;->i:I

    .line 23
    .line 24
    iget-object v3, p0, Lgr0/b;->e:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v5, p0, Lgr0/b;->f:Lx2/s;

    .line 27
    .line 28
    iget-boolean v6, p0, Lgr0/b;->g:Z

    .line 29
    .line 30
    invoke-static/range {v1 .. v6}, Lxf0/i0;->u(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 31
    .line 32
    .line 33
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    move-object v3, p1

    .line 37
    check-cast v3, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget p1, p0, Lgr0/b;->h:I

    .line 45
    .line 46
    or-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v1, p0, Lgr0/b;->i:I

    .line 53
    .line 54
    iget-object v2, p0, Lgr0/b;->e:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v4, p0, Lgr0/b;->f:Lx2/s;

    .line 57
    .line 58
    iget-boolean v5, p0, Lgr0/b;->g:Z

    .line 59
    .line 60
    invoke-static/range {v0 .. v5}, Llp/qa;->a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :pswitch_1
    move-object v3, p1

    .line 65
    check-cast v3, Ll2/o;

    .line 66
    .line 67
    check-cast p2, Ljava/lang/Integer;

    .line 68
    .line 69
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget p1, p0, Lgr0/b;->h:I

    .line 73
    .line 74
    or-int/lit8 p1, p1, 0x1

    .line 75
    .line 76
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget v1, p0, Lgr0/b;->i:I

    .line 81
    .line 82
    iget-object v2, p0, Lgr0/b;->e:Ljava/lang/String;

    .line 83
    .line 84
    iget-object v4, p0, Lgr0/b;->f:Lx2/s;

    .line 85
    .line 86
    iget-boolean v5, p0, Lgr0/b;->g:Z

    .line 87
    .line 88
    invoke-static/range {v0 .. v5}, Llp/qa;->a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :pswitch_2
    move-object v3, p1

    .line 93
    check-cast v3, Ll2/o;

    .line 94
    .line 95
    check-cast p2, Ljava/lang/Integer;

    .line 96
    .line 97
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    iget p1, p0, Lgr0/b;->h:I

    .line 101
    .line 102
    or-int/lit8 p1, p1, 0x1

    .line 103
    .line 104
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    iget v1, p0, Lgr0/b;->i:I

    .line 109
    .line 110
    iget-object v2, p0, Lgr0/b;->e:Ljava/lang/String;

    .line 111
    .line 112
    iget-object v4, p0, Lgr0/b;->f:Lx2/s;

    .line 113
    .line 114
    iget-boolean v5, p0, Lgr0/b;->g:Z

    .line 115
    .line 116
    invoke-static/range {v0 .. v5}, Lgr0/a;->b(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 117
    .line 118
    .line 119
    goto :goto_0

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
