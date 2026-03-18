.class public final synthetic Ld80/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;IIZ)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld80/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Ld80/g;->f:I

    iput-object p1, p0, Ld80/g;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Ld80/g;->e:Z

    iput p3, p0, Ld80/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;ZII)V
    .locals 1

    .line 2
    const/4 v0, 0x3

    iput v0, p0, Ld80/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld80/g;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Ld80/g;->e:Z

    iput p3, p0, Ld80/g;->f:I

    iput p4, p0, Ld80/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/n;III)V
    .locals 0

    .line 3
    iput p5, p0, Ld80/g;->d:I

    iput-boolean p1, p0, Ld80/g;->e:Z

    iput-object p2, p0, Ld80/g;->h:Ljava/lang/Object;

    iput p3, p0, Ld80/g;->f:I

    iput p4, p0, Ld80/g;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ld80/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld80/g;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/List;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget p2, p0, Ld80/g;->f:I

    .line 18
    .line 19
    or-int/lit8 p2, p2, 0x1

    .line 20
    .line 21
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    iget-boolean v1, p0, Ld80/g;->e:Z

    .line 26
    .line 27
    iget p0, p0, Ld80/g;->g:I

    .line 28
    .line 29
    invoke-static {v0, v1, p1, p2, p0}, Lxk0/h;->o0(Ljava/util/List;ZLl2/o;II)V

    .line 30
    .line 31
    .line 32
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    iget-object v0, p0, Ld80/g;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lay0/n;

    .line 38
    .line 39
    check-cast p1, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget p2, p0, Ld80/g;->f:I

    .line 47
    .line 48
    or-int/lit8 p2, p2, 0x1

    .line 49
    .line 50
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    iget-boolean v1, p0, Ld80/g;->e:Z

    .line 55
    .line 56
    iget p0, p0, Ld80/g;->g:I

    .line 57
    .line 58
    invoke-static {v1, v0, p1, p2, p0}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_1
    iget-object v0, p0, Ld80/g;->h:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lt2/b;

    .line 65
    .line 66
    check-cast p1, Ll2/o;

    .line 67
    .line 68
    check-cast p2, Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    iget p2, p0, Ld80/g;->f:I

    .line 74
    .line 75
    or-int/lit8 p2, p2, 0x1

    .line 76
    .line 77
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    iget-boolean v1, p0, Ld80/g;->e:Z

    .line 82
    .line 83
    iget p0, p0, Ld80/g;->g:I

    .line 84
    .line 85
    invoke-static {v1, v0, p1, p2, p0}, Llp/pb;->b(ZLt2/b;Ll2/o;II)V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :pswitch_2
    iget-object v0, p0, Ld80/g;->h:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Ljava/lang/String;

    .line 92
    .line 93
    check-cast p1, Ll2/o;

    .line 94
    .line 95
    check-cast p2, Ljava/lang/Integer;

    .line 96
    .line 97
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    iget p2, p0, Ld80/g;->g:I

    .line 101
    .line 102
    or-int/lit8 p2, p2, 0x1

    .line 103
    .line 104
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    iget v1, p0, Ld80/g;->f:I

    .line 109
    .line 110
    iget-boolean p0, p0, Ld80/g;->e:Z

    .line 111
    .line 112
    invoke-static {v1, v0, p0, p1, p2}, Ld80/b;->t(ILjava/lang/String;ZLl2/o;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
