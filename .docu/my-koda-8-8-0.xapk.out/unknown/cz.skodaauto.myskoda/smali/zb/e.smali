.class public final synthetic Lzb/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lt2/b;

.field public final synthetic e:Ls1/e;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:J

.field public final synthetic h:Z

.field public final synthetic i:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;Ls1/e;Lay0/n;JZLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzb/e;->d:Lt2/b;

    .line 5
    .line 6
    iput-object p2, p0, Lzb/e;->e:Ls1/e;

    .line 7
    .line 8
    iput-object p3, p0, Lzb/e;->f:Lay0/n;

    .line 9
    .line 10
    iput-wide p4, p0, Lzb/e;->g:J

    .line 11
    .line 12
    iput-boolean p6, p0, Lzb/e;->h:Z

    .line 13
    .line 14
    iput-object p7, p0, Lzb/e;->i:Lt2/b;

    .line 15
    .line 16
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
    const p1, 0x30007

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v8

    .line 16
    iget-object v0, p0, Lzb/e;->d:Lt2/b;

    .line 17
    .line 18
    iget-object v1, p0, Lzb/e;->e:Ls1/e;

    .line 19
    .line 20
    iget-object v2, p0, Lzb/e;->f:Lay0/n;

    .line 21
    .line 22
    iget-wide v3, p0, Lzb/e;->g:J

    .line 23
    .line 24
    iget-boolean v5, p0, Lzb/e;->h:Z

    .line 25
    .line 26
    iget-object v6, p0, Lzb/e;->i:Lt2/b;

    .line 27
    .line 28
    invoke-static/range {v0 .. v8}, Lzb/b;->b(Lt2/b;Ls1/e;Lay0/n;JZLt2/b;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
