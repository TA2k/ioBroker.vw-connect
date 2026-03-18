.class public final synthetic Lf71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;IZLay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    const/4 p6, 0x0

    iput p6, p0, Lf71/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf71/b;->e:Lx2/s;

    iput p2, p0, Lf71/b;->i:I

    iput-boolean p3, p0, Lf71/b;->f:Z

    iput-object p4, p0, Lf71/b;->g:Lay0/a;

    iput-object p5, p0, Lf71/b;->h:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ZLay0/a;Lay0/a;II)V
    .locals 0

    .line 2
    iput p6, p0, Lf71/b;->d:I

    iput-object p1, p0, Lf71/b;->e:Lx2/s;

    iput-boolean p2, p0, Lf71/b;->f:Z

    iput-object p3, p0, Lf71/b;->g:Lay0/a;

    iput-object p4, p0, Lf71/b;->h:Lay0/a;

    iput p5, p0, Lf71/b;->i:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lf71/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lf71/b;->i:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget-object v1, p0, Lf71/b;->e:Lx2/s;

    .line 23
    .line 24
    iget-boolean v2, p0, Lf71/b;->f:Z

    .line 25
    .line 26
    iget-object v3, p0, Lf71/b;->g:Lay0/a;

    .line 27
    .line 28
    iget-object v4, p0, Lf71/b;->h:Lay0/a;

    .line 29
    .line 30
    invoke-static/range {v1 .. v6}, Lv50/a;->i(Lx2/s;ZLay0/a;Lay0/a;Ll2/o;I)V

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
    move-object v4, p1

    .line 37
    check-cast v4, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget p1, p0, Lf71/b;->i:I

    .line 45
    .line 46
    or-int/lit8 p1, p1, 0x1

    .line 47
    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v5

    .line 52
    iget-object v0, p0, Lf71/b;->e:Lx2/s;

    .line 53
    .line 54
    iget-boolean v1, p0, Lf71/b;->f:Z

    .line 55
    .line 56
    iget-object v2, p0, Lf71/b;->g:Lay0/a;

    .line 57
    .line 58
    iget-object v3, p0, Lf71/b;->h:Lay0/a;

    .line 59
    .line 60
    invoke-static/range {v0 .. v5}, Lv50/a;->i(Lx2/s;ZLay0/a;Lay0/a;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :pswitch_1
    move-object v5, p1

    .line 65
    check-cast v5, Ll2/o;

    .line 66
    .line 67
    check-cast p2, Ljava/lang/Integer;

    .line 68
    .line 69
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    const/4 p1, 0x1

    .line 73
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    iget-object v0, p0, Lf71/b;->e:Lx2/s;

    .line 78
    .line 79
    iget v1, p0, Lf71/b;->i:I

    .line 80
    .line 81
    iget-boolean v2, p0, Lf71/b;->f:Z

    .line 82
    .line 83
    iget-object v3, p0, Lf71/b;->g:Lay0/a;

    .line 84
    .line 85
    iget-object v4, p0, Lf71/b;->h:Lay0/a;

    .line 86
    .line 87
    invoke-static/range {v0 .. v6}, Lkp/r7;->a(Lx2/s;IZLay0/a;Lay0/a;Ll2/o;I)V

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
