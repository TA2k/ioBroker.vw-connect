.class public final synthetic Lf71/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:J

.field public final synthetic j:I

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lx2/s;ZZJLay0/a;Lay0/a;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lf71/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf71/d;->g:Lx2/s;

    iput-boolean p2, p0, Lf71/d;->e:Z

    iput-boolean p3, p0, Lf71/d;->h:Z

    iput-wide p4, p0, Lf71/d;->i:J

    iput-object p6, p0, Lf71/d;->f:Lay0/a;

    iput-object p7, p0, Lf71/d;->k:Ljava/lang/Object;

    iput p8, p0, Lf71/d;->j:I

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/String;Lay0/a;Lx2/s;ZJII)V
    .locals 0

    .line 2
    const/4 p8, 0x1

    iput p8, p0, Lf71/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lf71/d;->e:Z

    iput-object p2, p0, Lf71/d;->k:Ljava/lang/Object;

    iput-object p3, p0, Lf71/d;->f:Lay0/a;

    iput-object p4, p0, Lf71/d;->g:Lx2/s;

    iput-boolean p5, p0, Lf71/d;->h:Z

    iput-wide p6, p0, Lf71/d;->i:J

    iput p9, p0, Lf71/d;->j:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lf71/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf71/d;->k:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, Ljava/lang/String;

    .line 10
    .line 11
    move-object v8, p1

    .line 12
    check-cast v8, Ll2/o;

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
    move-result v9

    .line 24
    iget-boolean v1, p0, Lf71/d;->e:Z

    .line 25
    .line 26
    iget-object v3, p0, Lf71/d;->f:Lay0/a;

    .line 27
    .line 28
    iget-object v4, p0, Lf71/d;->g:Lx2/s;

    .line 29
    .line 30
    iget-boolean v5, p0, Lf71/d;->h:Z

    .line 31
    .line 32
    iget-wide v6, p0, Lf71/d;->i:J

    .line 33
    .line 34
    iget v10, p0, Lf71/d;->j:I

    .line 35
    .line 36
    invoke-static/range {v1 .. v10}, Li91/j0;->c0(ZLjava/lang/String;Lay0/a;Lx2/s;ZJLl2/o;II)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    iget-object v0, p0, Lf71/d;->k:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v7, v0

    .line 45
    check-cast v7, Lay0/a;

    .line 46
    .line 47
    move-object v8, p1

    .line 48
    check-cast v8, Ll2/o;

    .line 49
    .line 50
    check-cast p2, Ljava/lang/Integer;

    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    iget p1, p0, Lf71/d;->j:I

    .line 56
    .line 57
    or-int/lit8 p1, p1, 0x1

    .line 58
    .line 59
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    iget-object v1, p0, Lf71/d;->g:Lx2/s;

    .line 64
    .line 65
    iget-boolean v2, p0, Lf71/d;->e:Z

    .line 66
    .line 67
    iget-boolean v3, p0, Lf71/d;->h:Z

    .line 68
    .line 69
    iget-wide v4, p0, Lf71/d;->i:J

    .line 70
    .line 71
    iget-object v6, p0, Lf71/d;->f:Lay0/a;

    .line 72
    .line 73
    invoke-static/range {v1 .. v9}, Lf71/f;->a(Lx2/s;ZZJLay0/a;Lay0/a;Ll2/o;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
