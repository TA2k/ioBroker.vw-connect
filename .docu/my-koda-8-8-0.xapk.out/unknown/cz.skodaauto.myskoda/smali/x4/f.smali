.class public final Lx4/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lx2/j;

.field public final synthetic g:J

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lx4/w;

.field public final synthetic j:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/j;JLay0/a;Lx4/w;Lt2/b;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/f;->f:Lx2/j;

    .line 2
    .line 3
    iput-wide p2, p0, Lx4/f;->g:J

    .line 4
    .line 5
    iput-object p4, p0, Lx4/f;->h:Lay0/a;

    .line 6
    .line 7
    iput-object p5, p0, Lx4/f;->i:Lx4/w;

    .line 8
    .line 9
    iput-object p6, p0, Lx4/f;->j:Lt2/b;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    move-object v6, p1

    .line 2
    check-cast v6, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    const/16 p1, 0x6007

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v7

    .line 15
    iget-object v0, p0, Lx4/f;->f:Lx2/j;

    .line 16
    .line 17
    iget-wide v1, p0, Lx4/f;->g:J

    .line 18
    .line 19
    iget-object v3, p0, Lx4/f;->h:Lay0/a;

    .line 20
    .line 21
    iget-object v4, p0, Lx4/f;->i:Lx4/w;

    .line 22
    .line 23
    iget-object v5, p0, Lx4/f;->j:Lt2/b;

    .line 24
    .line 25
    invoke-static/range {v0 .. v7}, Lx4/i;->b(Lx2/j;JLay0/a;Lx4/w;Lt2/b;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
