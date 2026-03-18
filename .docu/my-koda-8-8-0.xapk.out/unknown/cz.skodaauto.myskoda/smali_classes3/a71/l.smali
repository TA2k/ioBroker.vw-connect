.class public final synthetic La71/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lt2/b;

.field public final synthetic n:Lt2/b;


# direct methods
.method public synthetic constructor <init>(ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, La71/l;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, La71/l;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, La71/l;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, La71/l;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, La71/l;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, La71/l;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, La71/l;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, La71/l;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, La71/l;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, La71/l;->m:Lt2/b;

    .line 23
    .line 24
    iput-object p11, p0, La71/l;->n:Lt2/b;

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
    const/4 p1, 0x7

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v12

    .line 14
    iget-boolean v0, p0, La71/l;->d:Z

    .line 15
    .line 16
    iget-boolean v1, p0, La71/l;->e:Z

    .line 17
    .line 18
    iget-boolean v2, p0, La71/l;->f:Z

    .line 19
    .line 20
    iget-boolean v3, p0, La71/l;->g:Z

    .line 21
    .line 22
    iget-object v4, p0, La71/l;->h:Lay0/a;

    .line 23
    .line 24
    iget-object v5, p0, La71/l;->i:Lay0/a;

    .line 25
    .line 26
    iget-object v6, p0, La71/l;->j:Lay0/a;

    .line 27
    .line 28
    iget-object v7, p0, La71/l;->k:Lay0/a;

    .line 29
    .line 30
    iget-object v8, p0, La71/l;->l:Lay0/a;

    .line 31
    .line 32
    iget-object v9, p0, La71/l;->m:Lt2/b;

    .line 33
    .line 34
    iget-object v10, p0, La71/l;->n:Lt2/b;

    .line 35
    .line 36
    invoke-static/range {v0 .. v12}, La71/b;->b(ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0
.end method
