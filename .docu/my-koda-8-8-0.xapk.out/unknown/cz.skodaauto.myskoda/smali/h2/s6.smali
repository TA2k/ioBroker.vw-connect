.class public final synthetic Lh2/s6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/v6;

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Li1/l;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lh2/eb;

.field public final synthetic j:Le3/n0;

.field public final synthetic k:F

.field public final synthetic l:F

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Lh2/v6;ZZLi1/l;Lx2/s;Lh2/eb;Le3/n0;FFII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/s6;->d:Lh2/v6;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/s6;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/s6;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lh2/s6;->g:Li1/l;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/s6;->h:Lx2/s;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/s6;->i:Lh2/eb;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/s6;->j:Le3/n0;

    .line 17
    .line 18
    iput p8, p0, Lh2/s6;->k:F

    .line 19
    .line 20
    iput p9, p0, Lh2/s6;->l:F

    .line 21
    .line 22
    iput p10, p0, Lh2/s6;->m:I

    .line 23
    .line 24
    iput p11, p0, Lh2/s6;->n:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v9, p1

    .line 2
    check-cast v9, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lh2/s6;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v10

    .line 17
    iget-object v0, p0, Lh2/s6;->d:Lh2/v6;

    .line 18
    .line 19
    iget-boolean v1, p0, Lh2/s6;->e:Z

    .line 20
    .line 21
    iget-boolean v2, p0, Lh2/s6;->f:Z

    .line 22
    .line 23
    iget-object v3, p0, Lh2/s6;->g:Li1/l;

    .line 24
    .line 25
    iget-object v4, p0, Lh2/s6;->h:Lx2/s;

    .line 26
    .line 27
    iget-object v5, p0, Lh2/s6;->i:Lh2/eb;

    .line 28
    .line 29
    iget-object v6, p0, Lh2/s6;->j:Le3/n0;

    .line 30
    .line 31
    iget v7, p0, Lh2/s6;->k:F

    .line 32
    .line 33
    iget v8, p0, Lh2/s6;->l:F

    .line 34
    .line 35
    iget v11, p0, Lh2/s6;->n:I

    .line 36
    .line 37
    invoke-virtual/range {v0 .. v11}, Lh2/v6;->a(ZZLi1/l;Lx2/s;Lh2/eb;Le3/n0;FFLl2/o;II)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method
