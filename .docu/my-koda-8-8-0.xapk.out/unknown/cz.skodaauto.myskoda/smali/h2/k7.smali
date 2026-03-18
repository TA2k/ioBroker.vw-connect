.class public final synthetic Lh2/k7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:I

.field public final synthetic h:F

.field public final synthetic i:I

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;JJIFII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/k7;->d:Lx2/s;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/k7;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Lh2/k7;->f:J

    .line 9
    .line 10
    iput p6, p0, Lh2/k7;->g:I

    .line 11
    .line 12
    iput p7, p0, Lh2/k7;->h:F

    .line 13
    .line 14
    iput p8, p0, Lh2/k7;->i:I

    .line 15
    .line 16
    iput p9, p0, Lh2/k7;->j:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lh2/k7;->i:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v8

    .line 17
    iget-object v0, p0, Lh2/k7;->d:Lx2/s;

    .line 18
    .line 19
    iget-wide v1, p0, Lh2/k7;->e:J

    .line 20
    .line 21
    iget-wide v3, p0, Lh2/k7;->f:J

    .line 22
    .line 23
    iget v5, p0, Lh2/k7;->g:I

    .line 24
    .line 25
    iget v6, p0, Lh2/k7;->h:F

    .line 26
    .line 27
    iget v9, p0, Lh2/k7;->j:I

    .line 28
    .line 29
    invoke-static/range {v0 .. v9}, Lh2/n7;->d(Lx2/s;JJIFLl2/o;II)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
