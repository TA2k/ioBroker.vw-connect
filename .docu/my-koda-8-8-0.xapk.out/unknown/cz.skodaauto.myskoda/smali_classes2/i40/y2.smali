.class public final synthetic Li40/y2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:Lx2/s;

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Li91/j1;JJLx2/s;II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/y2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/y2;->j:Ljava/lang/Object;

    iput-object p2, p0, Li40/y2;->k:Ljava/lang/Object;

    iput-wide p3, p0, Li40/y2;->e:J

    iput-wide p5, p0, Li40/y2;->f:J

    iput-object p7, p0, Li40/y2;->g:Lx2/s;

    iput p8, p0, Li40/y2;->h:I

    iput p9, p0, Li40/y2;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;ILg4/p0;Lg4/p0;JJII)V
    .locals 0

    .line 2
    const/4 p9, 0x0

    iput p9, p0, Li40/y2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/y2;->g:Lx2/s;

    iput p2, p0, Li40/y2;->h:I

    iput-object p3, p0, Li40/y2;->j:Ljava/lang/Object;

    iput-object p4, p0, Li40/y2;->k:Ljava/lang/Object;

    iput-wide p5, p0, Li40/y2;->e:J

    iput-wide p7, p0, Li40/y2;->f:J

    iput p10, p0, Li40/y2;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Li40/y2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li40/y2;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Li40/y2;->k:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Li91/j1;

    .line 15
    .line 16
    move-object v8, p1

    .line 17
    check-cast v8, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget p1, p0, Li40/y2;->h:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v9

    .line 32
    iget-wide v3, p0, Li40/y2;->e:J

    .line 33
    .line 34
    iget-wide v5, p0, Li40/y2;->f:J

    .line 35
    .line 36
    iget-object v7, p0, Li40/y2;->g:Lx2/s;

    .line 37
    .line 38
    iget v10, p0, Li40/y2;->i:I

    .line 39
    .line 40
    invoke-static/range {v1 .. v10}, Li91/j0;->z(Ljava/lang/String;Li91/j1;JJLx2/s;Ll2/o;II)V

    .line 41
    .line 42
    .line 43
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    iget-object v0, p0, Li40/y2;->j:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v3, v0

    .line 49
    check-cast v3, Lg4/p0;

    .line 50
    .line 51
    iget-object v0, p0, Li40/y2;->k:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v4, v0

    .line 54
    check-cast v4, Lg4/p0;

    .line 55
    .line 56
    move-object v9, p1

    .line 57
    check-cast v9, Ll2/o;

    .line 58
    .line 59
    check-cast p2, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    const/4 p1, 0x1

    .line 65
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    iget-object v1, p0, Li40/y2;->g:Lx2/s;

    .line 70
    .line 71
    iget v2, p0, Li40/y2;->h:I

    .line 72
    .line 73
    iget-wide v5, p0, Li40/y2;->e:J

    .line 74
    .line 75
    iget-wide v7, p0, Li40/y2;->f:J

    .line 76
    .line 77
    iget v11, p0, Li40/y2;->i:I

    .line 78
    .line 79
    invoke-static/range {v1 .. v11}, Li40/l1;->a0(Lx2/s;ILg4/p0;Lg4/p0;JJLl2/o;II)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
