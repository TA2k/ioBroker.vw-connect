.class public final synthetic Lh2/q4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:F

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;FJIII)V
    .locals 0

    .line 1
    iput p7, p0, Lh2/q4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/q4;->e:Lx2/s;

    .line 4
    .line 5
    iput p2, p0, Lh2/q4;->f:F

    .line 6
    .line 7
    iput-wide p3, p0, Lh2/q4;->g:J

    .line 8
    .line 9
    iput p5, p0, Lh2/q4;->h:I

    .line 10
    .line 11
    iput p6, p0, Lh2/q4;->i:I

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lh2/q4;->d:I

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
    iget p1, p0, Lh2/q4;->h:I

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
    iget-object v1, p0, Lh2/q4;->e:Lx2/s;

    .line 23
    .line 24
    iget v2, p0, Lh2/q4;->f:F

    .line 25
    .line 26
    iget-wide v3, p0, Lh2/q4;->g:J

    .line 27
    .line 28
    iget v7, p0, Lh2/q4;->i:I

    .line 29
    .line 30
    invoke-static/range {v1 .. v7}, Lh2/r;->v(Lx2/s;FJLl2/o;II)V

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
    iget p1, p0, Lh2/q4;->h:I

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
    iget-object v0, p0, Lh2/q4;->e:Lx2/s;

    .line 53
    .line 54
    iget v1, p0, Lh2/q4;->f:F

    .line 55
    .line 56
    iget-wide v2, p0, Lh2/q4;->g:J

    .line 57
    .line 58
    iget v6, p0, Lh2/q4;->i:I

    .line 59
    .line 60
    invoke-static/range {v0 .. v6}, Lh2/r;->k(Lx2/s;FJLl2/o;II)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
