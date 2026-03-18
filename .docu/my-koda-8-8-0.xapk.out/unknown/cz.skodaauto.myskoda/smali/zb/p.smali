.class public final synthetic Lzb/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:J

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Ls1/e;

.field public final synthetic i:Lyj/b;

.field public final synthetic j:Lt2/b;

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(JJFFLs1/e;Lyj/b;Lt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lzb/p;->d:J

    .line 5
    .line 6
    iput-wide p3, p0, Lzb/p;->e:J

    .line 7
    .line 8
    iput p5, p0, Lzb/p;->f:F

    .line 9
    .line 10
    iput p6, p0, Lzb/p;->g:F

    .line 11
    .line 12
    iput-object p7, p0, Lzb/p;->h:Ls1/e;

    .line 13
    .line 14
    iput-object p8, p0, Lzb/p;->i:Lyj/b;

    .line 15
    .line 16
    iput-object p9, p0, Lzb/p;->j:Lt2/b;

    .line 17
    .line 18
    iput p10, p0, Lzb/p;->k:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

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
    iget p1, p0, Lzb/p;->k:I

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
    iget-wide v0, p0, Lzb/p;->d:J

    .line 18
    .line 19
    iget-wide v2, p0, Lzb/p;->e:J

    .line 20
    .line 21
    iget v4, p0, Lzb/p;->f:F

    .line 22
    .line 23
    iget v5, p0, Lzb/p;->g:F

    .line 24
    .line 25
    iget-object v6, p0, Lzb/p;->h:Ls1/e;

    .line 26
    .line 27
    iget-object v7, p0, Lzb/p;->i:Lyj/b;

    .line 28
    .line 29
    iget-object v8, p0, Lzb/p;->j:Lt2/b;

    .line 30
    .line 31
    invoke-static/range {v0 .. v10}, Lzb/b;->h(JJFFLs1/e;Lyj/b;Lt2/b;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
