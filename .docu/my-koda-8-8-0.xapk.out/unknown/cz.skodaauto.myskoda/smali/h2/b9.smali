.class public final synthetic Lh2/b9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lh2/u8;

.field public final synthetic j:Li1/l;

.field public final synthetic k:I

.field public final synthetic l:Lt2/b;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:Lgy0/f;


# direct methods
.method public synthetic constructor <init>(FLay0/k;Lx2/s;ZLay0/a;Lh2/u8;Li1/l;ILt2/b;Lt2/b;Lgy0/f;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/b9;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Lh2/b9;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/b9;->f:Lx2/s;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/b9;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lh2/b9;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/b9;->i:Lh2/u8;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/b9;->j:Li1/l;

    .line 17
    .line 18
    iput p8, p0, Lh2/b9;->k:I

    .line 19
    .line 20
    iput-object p9, p0, Lh2/b9;->l:Lt2/b;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/b9;->m:Lt2/b;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/b9;->n:Lgy0/f;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v11, p1

    .line 2
    check-cast v11, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const p1, 0x36000001

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v12

    .line 16
    iget v0, p0, Lh2/b9;->d:F

    .line 17
    .line 18
    iget-object v1, p0, Lh2/b9;->e:Lay0/k;

    .line 19
    .line 20
    iget-object v2, p0, Lh2/b9;->f:Lx2/s;

    .line 21
    .line 22
    iget-boolean v3, p0, Lh2/b9;->g:Z

    .line 23
    .line 24
    iget-object v4, p0, Lh2/b9;->h:Lay0/a;

    .line 25
    .line 26
    iget-object v5, p0, Lh2/b9;->i:Lh2/u8;

    .line 27
    .line 28
    iget-object v6, p0, Lh2/b9;->j:Li1/l;

    .line 29
    .line 30
    iget v7, p0, Lh2/b9;->k:I

    .line 31
    .line 32
    iget-object v8, p0, Lh2/b9;->l:Lt2/b;

    .line 33
    .line 34
    iget-object v9, p0, Lh2/b9;->m:Lt2/b;

    .line 35
    .line 36
    iget-object v10, p0, Lh2/b9;->n:Lgy0/f;

    .line 37
    .line 38
    invoke-static/range {v0 .. v12}, Lh2/q9;->d(FLay0/k;Lx2/s;ZLay0/a;Lh2/u8;Li1/l;ILt2/b;Lt2/b;Lgy0/f;Ll2/o;I)V

    .line 39
    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0
.end method
