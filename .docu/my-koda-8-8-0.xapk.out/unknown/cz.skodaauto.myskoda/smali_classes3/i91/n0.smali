.class public final synthetic Li91/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:I

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(JLjava/lang/String;III)V
    .locals 0

    .line 1
    const/4 p5, 0x2

    iput p5, p0, Li91/n0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Li91/n0;->f:Ljava/lang/Object;

    iput p4, p0, Li91/n0;->g:I

    iput-wide p1, p0, Li91/n0;->e:J

    iput p6, p0, Li91/n0;->h:I

    return-void
.end method

.method public synthetic constructor <init>(JLx2/s;II)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/n0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Li91/n0;->e:J

    iput-object p3, p0, Li91/n0;->f:Ljava/lang/Object;

    iput p4, p0, Li91/n0;->g:I

    iput p5, p0, Li91/n0;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;JII)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Li91/n0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/n0;->f:Ljava/lang/Object;

    iput-wide p2, p0, Li91/n0;->e:J

    iput p4, p0, Li91/n0;->g:I

    iput p5, p0, Li91/n0;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/n0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/n0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    check-cast v5, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v6

    .line 24
    iget v2, p0, Li91/n0;->g:I

    .line 25
    .line 26
    iget-wide v3, p0, Li91/n0;->e:J

    .line 27
    .line 28
    iget v7, p0, Li91/n0;->h:I

    .line 29
    .line 30
    invoke-static/range {v1 .. v7}, Lv50/a;->h0(Ljava/lang/String;IJLl2/o;II)V

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
    iget-object v0, p0, Li91/n0;->f:Ljava/lang/Object;

    .line 37
    .line 38
    move-object v6, v0

    .line 39
    check-cast v6, Lx2/s;

    .line 40
    .line 41
    move-object v5, p1

    .line 42
    check-cast v5, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget p1, p0, Li91/n0;->g:I

    .line 50
    .line 51
    or-int/lit8 p1, p1, 0x1

    .line 52
    .line 53
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    iget v2, p0, Li91/n0;->h:I

    .line 58
    .line 59
    iget-wide v3, p0, Li91/n0;->e:J

    .line 60
    .line 61
    invoke-static/range {v1 .. v6}, Lzj0/d;->h(IIJLl2/o;Lx2/s;)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :pswitch_1
    iget-object v0, p0, Li91/n0;->f:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v6, v0

    .line 68
    check-cast v6, Lx2/s;

    .line 69
    .line 70
    move-object v5, p1

    .line 71
    check-cast v5, Ll2/o;

    .line 72
    .line 73
    check-cast p2, Ljava/lang/Integer;

    .line 74
    .line 75
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    iget p1, p0, Li91/n0;->g:I

    .line 79
    .line 80
    or-int/lit8 p1, p1, 0x1

    .line 81
    .line 82
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    iget v2, p0, Li91/n0;->h:I

    .line 87
    .line 88
    iget-wide v3, p0, Li91/n0;->e:J

    .line 89
    .line 90
    invoke-static/range {v1 .. v6}, Li91/j0;->A0(IIJLl2/o;Lx2/s;)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
