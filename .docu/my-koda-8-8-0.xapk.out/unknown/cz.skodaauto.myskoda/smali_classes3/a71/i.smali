.class public final synthetic La71/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lt2/b;

.field public final synthetic o:Lt2/b;

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La71/i;->d:Lx2/s;

    .line 5
    .line 6
    iput-boolean p2, p0, La71/i;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, La71/i;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, La71/i;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, La71/i;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, La71/i;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, La71/i;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, La71/i;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, La71/i;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, La71/i;->m:Lay0/a;

    .line 23
    .line 24
    iput-object p11, p0, La71/i;->n:Lt2/b;

    .line 25
    .line 26
    iput-object p12, p0, La71/i;->o:Lt2/b;

    .line 27
    .line 28
    iput p13, p0, La71/i;->p:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v12, p1

    .line 2
    check-cast v12, Ll2/o;

    .line 3
    .line 4
    move-object/from16 v0, p2

    .line 5
    .line 6
    check-cast v0, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget v0, p0, La71/i;->p:I

    .line 12
    .line 13
    or-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v13

    .line 19
    iget-object v0, p0, La71/i;->d:Lx2/s;

    .line 20
    .line 21
    iget-boolean v1, p0, La71/i;->e:Z

    .line 22
    .line 23
    iget-boolean v2, p0, La71/i;->f:Z

    .line 24
    .line 25
    iget-boolean v3, p0, La71/i;->g:Z

    .line 26
    .line 27
    iget-boolean v4, p0, La71/i;->h:Z

    .line 28
    .line 29
    iget-object v5, p0, La71/i;->i:Lay0/a;

    .line 30
    .line 31
    iget-object v6, p0, La71/i;->j:Lay0/a;

    .line 32
    .line 33
    iget-object v7, p0, La71/i;->k:Lay0/a;

    .line 34
    .line 35
    iget-object v8, p0, La71/i;->l:Lay0/a;

    .line 36
    .line 37
    iget-object v9, p0, La71/i;->m:Lay0/a;

    .line 38
    .line 39
    iget-object v10, p0, La71/i;->n:Lt2/b;

    .line 40
    .line 41
    iget-object v11, p0, La71/i;->o:Lt2/b;

    .line 42
    .line 43
    invoke-static/range {v0 .. v13}, La71/b;->a(Lx2/s;ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0
.end method
