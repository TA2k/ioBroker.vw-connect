.class public final synthetic Lh2/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lt2/b;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lt2/b;

.field public final synthetic g:Lt2/b;

.field public final synthetic h:F

.field public final synthetic i:Lk1/q1;

.field public final synthetic j:Lh2/zb;


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lx2/s;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/p;->d:Lt2/b;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/p;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/p;->f:Lt2/b;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/p;->g:Lt2/b;

    .line 11
    .line 12
    iput p5, p0, Lh2/p;->h:F

    .line 13
    .line 14
    iput-object p6, p0, Lh2/p;->i:Lk1/q1;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/p;->j:Lh2/zb;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

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
    const/16 p1, 0xc07

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v8

    .line 15
    iget-object v0, p0, Lh2/p;->d:Lt2/b;

    .line 16
    .line 17
    iget-object v1, p0, Lh2/p;->e:Lx2/s;

    .line 18
    .line 19
    iget-object v2, p0, Lh2/p;->f:Lt2/b;

    .line 20
    .line 21
    iget-object v3, p0, Lh2/p;->g:Lt2/b;

    .line 22
    .line 23
    iget v4, p0, Lh2/p;->h:F

    .line 24
    .line 25
    iget-object v5, p0, Lh2/p;->i:Lk1/q1;

    .line 26
    .line 27
    iget-object v6, p0, Lh2/p;->j:Lh2/zb;

    .line 28
    .line 29
    invoke-static/range {v0 .. v8}, Lh2/q;->b(Lt2/b;Lx2/s;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
