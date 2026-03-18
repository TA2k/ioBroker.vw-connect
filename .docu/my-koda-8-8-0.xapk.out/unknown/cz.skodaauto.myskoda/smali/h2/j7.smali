.class public final synthetic Lh2/j7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:J

.field public final synthetic f:F

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:F

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;JFJIFII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/j7;->d:Lx2/s;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/j7;->e:J

    .line 7
    .line 8
    iput p4, p0, Lh2/j7;->f:F

    .line 9
    .line 10
    iput-wide p5, p0, Lh2/j7;->g:J

    .line 11
    .line 12
    iput p7, p0, Lh2/j7;->h:I

    .line 13
    .line 14
    iput p8, p0, Lh2/j7;->i:F

    .line 15
    .line 16
    iput p9, p0, Lh2/j7;->j:I

    .line 17
    .line 18
    iput p10, p0, Lh2/j7;->k:I

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
    iget p1, p0, Lh2/j7;->j:I

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
    iget-object v0, p0, Lh2/j7;->d:Lx2/s;

    .line 18
    .line 19
    iget-wide v1, p0, Lh2/j7;->e:J

    .line 20
    .line 21
    iget v3, p0, Lh2/j7;->f:F

    .line 22
    .line 23
    iget-wide v4, p0, Lh2/j7;->g:J

    .line 24
    .line 25
    iget v6, p0, Lh2/j7;->h:I

    .line 26
    .line 27
    iget v7, p0, Lh2/j7;->i:F

    .line 28
    .line 29
    iget v10, p0, Lh2/j7;->k:I

    .line 30
    .line 31
    invoke-static/range {v0 .. v10}, Lh2/n7;->a(Lx2/s;JFJIFLl2/o;II)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
