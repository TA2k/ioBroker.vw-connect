.class public final synthetic Li91/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lx2/s;ZJJII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li91/a0;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Li91/a0;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Li91/a0;->f:Lx2/s;

    .line 9
    .line 10
    iput-boolean p4, p0, Li91/a0;->g:Z

    .line 11
    .line 12
    iput-wide p5, p0, Li91/a0;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Li91/a0;->i:J

    .line 15
    .line 16
    iput p9, p0, Li91/a0;->j:I

    .line 17
    .line 18
    iput p10, p0, Li91/a0;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li91/a0;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    iget v0, p0, Li91/a0;->d:I

    .line 18
    .line 19
    iget-object v1, p0, Li91/a0;->e:Lay0/a;

    .line 20
    .line 21
    iget-object v2, p0, Li91/a0;->f:Lx2/s;

    .line 22
    .line 23
    iget-boolean v3, p0, Li91/a0;->g:Z

    .line 24
    .line 25
    iget-wide v4, p0, Li91/a0;->h:J

    .line 26
    .line 27
    iget-wide v6, p0, Li91/a0;->i:J

    .line 28
    .line 29
    iget v10, p0, Li91/a0;->k:I

    .line 30
    .line 31
    invoke-static/range {v0 .. v10}, Li91/j0;->y0(ILay0/a;Lx2/s;ZJJLl2/o;II)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
