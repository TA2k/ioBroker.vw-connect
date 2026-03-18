.class public final synthetic Lj2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lj2/h;

.field public final synthetic e:Lj2/p;

.field public final synthetic f:Z

.field public final synthetic g:Lx2/s;

.field public final synthetic h:F

.field public final synthetic i:Le3/n0;

.field public final synthetic j:J

.field public final synthetic k:F

.field public final synthetic l:Lt2/b;

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lj2/h;Lj2/p;ZLx2/s;FLe3/n0;JFLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/c;->d:Lj2/h;

    .line 5
    .line 6
    iput-object p2, p0, Lj2/c;->e:Lj2/p;

    .line 7
    .line 8
    iput-boolean p3, p0, Lj2/c;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lj2/c;->g:Lx2/s;

    .line 11
    .line 12
    iput p5, p0, Lj2/c;->h:F

    .line 13
    .line 14
    iput-object p6, p0, Lj2/c;->i:Le3/n0;

    .line 15
    .line 16
    iput-wide p7, p0, Lj2/c;->j:J

    .line 17
    .line 18
    iput p9, p0, Lj2/c;->k:F

    .line 19
    .line 20
    iput-object p10, p0, Lj2/c;->l:Lt2/b;

    .line 21
    .line 22
    iput p11, p0, Lj2/c;->m:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lj2/c;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v11

    .line 17
    iget-object v0, p0, Lj2/c;->d:Lj2/h;

    .line 18
    .line 19
    iget-object v1, p0, Lj2/c;->e:Lj2/p;

    .line 20
    .line 21
    iget-boolean v2, p0, Lj2/c;->f:Z

    .line 22
    .line 23
    iget-object v3, p0, Lj2/c;->g:Lx2/s;

    .line 24
    .line 25
    iget v4, p0, Lj2/c;->h:F

    .line 26
    .line 27
    iget-object v5, p0, Lj2/c;->i:Le3/n0;

    .line 28
    .line 29
    iget-wide v6, p0, Lj2/c;->j:J

    .line 30
    .line 31
    iget v8, p0, Lj2/c;->k:F

    .line 32
    .line 33
    iget-object v9, p0, Lj2/c;->l:Lt2/b;

    .line 34
    .line 35
    invoke-virtual/range {v0 .. v11}, Lj2/h;->b(Lj2/p;ZLx2/s;FLe3/n0;JFLt2/b;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
