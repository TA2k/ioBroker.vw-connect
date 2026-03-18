.class public final synthetic Lxf0/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:J

.field public final synthetic f:Lt2/b;

.field public final synthetic g:I

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;JLt2/b;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/g1;->d:Lx2/s;

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/g1;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lxf0/g1;->f:Lt2/b;

    .line 9
    .line 10
    iput p5, p0, Lxf0/g1;->g:I

    .line 11
    .line 12
    iput p6, p0, Lxf0/g1;->h:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lxf0/g1;->g:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    iget-object v0, p0, Lxf0/g1;->d:Lx2/s;

    .line 18
    .line 19
    iget-wide v1, p0, Lxf0/g1;->e:J

    .line 20
    .line 21
    iget-object v3, p0, Lxf0/g1;->f:Lt2/b;

    .line 22
    .line 23
    iget v6, p0, Lxf0/g1;->h:I

    .line 24
    .line 25
    invoke-static/range {v0 .. v6}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
