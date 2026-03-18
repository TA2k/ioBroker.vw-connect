.class public final Lv3/d1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Lv3/f1;

.field public final synthetic g:Lx2/r;

.field public final synthetic h:Lv3/d;

.field public final synthetic i:J

.field public final synthetic j:Lv3/s;

.field public final synthetic k:I

.field public final synthetic l:Z

.field public final synthetic m:F

.field public final synthetic n:Z


# direct methods
.method public constructor <init>(Lv3/f1;Lx2/r;Lv3/d;JLv3/s;IZFZ)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv3/d1;->f:Lv3/f1;

    .line 2
    .line 3
    iput-object p2, p0, Lv3/d1;->g:Lx2/r;

    .line 4
    .line 5
    iput-object p3, p0, Lv3/d1;->h:Lv3/d;

    .line 6
    .line 7
    iput-wide p4, p0, Lv3/d1;->i:J

    .line 8
    .line 9
    iput-object p6, p0, Lv3/d1;->j:Lv3/s;

    .line 10
    .line 11
    iput p7, p0, Lv3/d1;->k:I

    .line 12
    .line 13
    iput-boolean p8, p0, Lv3/d1;->l:Z

    .line 14
    .line 15
    iput p9, p0, Lv3/d1;->m:F

    .line 16
    .line 17
    iput-boolean p10, p0, Lv3/d1;->n:Z

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Lv3/d1;->h:Lv3/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lv3/d;->c()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lv3/d1;->g:Lx2/r;

    .line 8
    .line 9
    invoke-static {v1, v0}, Lv3/f;->e(Lv3/m;I)Lx2/r;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    iget v10, p0, Lv3/d1;->m:F

    .line 14
    .line 15
    iget-boolean v11, p0, Lv3/d1;->n:Z

    .line 16
    .line 17
    iget-object v2, p0, Lv3/d1;->f:Lv3/f1;

    .line 18
    .line 19
    iget-object v4, p0, Lv3/d1;->h:Lv3/d;

    .line 20
    .line 21
    iget-wide v5, p0, Lv3/d1;->i:J

    .line 22
    .line 23
    iget-object v7, p0, Lv3/d1;->j:Lv3/s;

    .line 24
    .line 25
    iget v8, p0, Lv3/d1;->k:I

    .line 26
    .line 27
    iget-boolean v9, p0, Lv3/d1;->l:Z

    .line 28
    .line 29
    invoke-virtual/range {v2 .. v11}, Lv3/f1;->t1(Lx2/r;Lv3/d;JLv3/s;IZFZ)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
