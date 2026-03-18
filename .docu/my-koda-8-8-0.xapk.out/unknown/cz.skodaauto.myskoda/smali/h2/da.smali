.class public final synthetic Lh2/da;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lt2/b;

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:Lg4/p0;

.field public final synthetic h:J

.field public final synthetic i:J


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lay0/n;Lay0/n;Lg4/p0;JJI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/da;->d:Lt2/b;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/da;->e:Lay0/n;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/da;->f:Lay0/n;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/da;->g:Lg4/p0;

    .line 11
    .line 12
    iput-wide p5, p0, Lh2/da;->h:J

    .line 13
    .line 14
    iput-wide p7, p0, Lh2/da;->i:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

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
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v9

    .line 14
    iget-object v0, p0, Lh2/da;->d:Lt2/b;

    .line 15
    .line 16
    iget-object v1, p0, Lh2/da;->e:Lay0/n;

    .line 17
    .line 18
    iget-object v2, p0, Lh2/da;->f:Lay0/n;

    .line 19
    .line 20
    iget-object v3, p0, Lh2/da;->g:Lg4/p0;

    .line 21
    .line 22
    iget-wide v4, p0, Lh2/da;->h:J

    .line 23
    .line 24
    iget-wide v6, p0, Lh2/da;->i:J

    .line 25
    .line 26
    invoke-static/range {v0 .. v9}, Lh2/ja;->a(Lt2/b;Lay0/n;Lay0/n;Lg4/p0;JJLl2/o;I)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method
