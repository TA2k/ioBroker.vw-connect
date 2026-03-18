.class public final synthetic Lh2/g9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lgy0/f;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Z

.field public final synthetic h:Lgy0/f;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lh2/u8;

.field public final synthetic k:Li1/l;

.field public final synthetic l:Li1/l;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:Lt2/b;

.field public final synthetic o:Lt2/b;

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Lgy0/f;Lay0/k;Lx2/s;ZLgy0/f;Lay0/a;Lh2/u8;Li1/l;Li1/l;Lt2/b;Lt2/b;Lt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/g9;->d:Lgy0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/g9;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/g9;->f:Lx2/s;

    .line 9
    .line 10
    iput-boolean p4, p0, Lh2/g9;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lh2/g9;->h:Lgy0/f;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/g9;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/g9;->j:Lh2/u8;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/g9;->k:Li1/l;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/g9;->l:Li1/l;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/g9;->m:Lt2/b;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/g9;->n:Lt2/b;

    .line 25
    .line 26
    iput-object p12, p0, Lh2/g9;->o:Lt2/b;

    .line 27
    .line 28
    iput p13, p0, Lh2/g9;->p:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v13, p1

    .line 4
    .line 5
    check-cast v13, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const v1, 0x30000001

    .line 15
    .line 16
    .line 17
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result v14

    .line 21
    iget-object v1, v0, Lh2/g9;->d:Lgy0/f;

    .line 22
    .line 23
    move-object v2, v1

    .line 24
    iget-object v1, v0, Lh2/g9;->e:Lay0/k;

    .line 25
    .line 26
    move-object v3, v2

    .line 27
    iget-object v2, v0, Lh2/g9;->f:Lx2/s;

    .line 28
    .line 29
    move-object v4, v3

    .line 30
    iget-boolean v3, v0, Lh2/g9;->g:Z

    .line 31
    .line 32
    move-object v5, v4

    .line 33
    iget-object v4, v0, Lh2/g9;->h:Lgy0/f;

    .line 34
    .line 35
    move-object v6, v5

    .line 36
    iget-object v5, v0, Lh2/g9;->i:Lay0/a;

    .line 37
    .line 38
    move-object v7, v6

    .line 39
    iget-object v6, v0, Lh2/g9;->j:Lh2/u8;

    .line 40
    .line 41
    move-object v8, v7

    .line 42
    iget-object v7, v0, Lh2/g9;->k:Li1/l;

    .line 43
    .line 44
    move-object v9, v8

    .line 45
    iget-object v8, v0, Lh2/g9;->l:Li1/l;

    .line 46
    .line 47
    move-object v10, v9

    .line 48
    iget-object v9, v0, Lh2/g9;->m:Lt2/b;

    .line 49
    .line 50
    move-object v11, v10

    .line 51
    iget-object v10, v0, Lh2/g9;->n:Lt2/b;

    .line 52
    .line 53
    move-object v12, v11

    .line 54
    iget-object v11, v0, Lh2/g9;->o:Lt2/b;

    .line 55
    .line 56
    iget v0, v0, Lh2/g9;->p:I

    .line 57
    .line 58
    move-object v15, v12

    .line 59
    move v12, v0

    .line 60
    move-object v0, v15

    .line 61
    invoke-static/range {v0 .. v14}, Lh2/q9;->a(Lgy0/f;Lay0/k;Lx2/s;ZLgy0/f;Lay0/a;Lh2/u8;Li1/l;Li1/l;Lt2/b;Lt2/b;Lt2/b;ILl2/o;I)V

    .line 62
    .line 63
    .line 64
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object v0
.end method
