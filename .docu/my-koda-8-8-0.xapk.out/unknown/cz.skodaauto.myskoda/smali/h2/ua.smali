.class public final synthetic Lh2/ua;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:Lt2/b;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(ZLay0/a;Lx2/s;JJLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lh2/ua;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ua;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/ua;->f:Lx2/s;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/ua;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Lh2/ua;->h:J

    .line 13
    .line 14
    iput-object p8, p0, Lh2/ua;->i:Lt2/b;

    .line 15
    .line 16
    iput p9, p0, Lh2/ua;->j:I

    .line 17
    .line 18
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
    iget p1, p0, Lh2/ua;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    iget-boolean v0, p0, Lh2/ua;->d:Z

    .line 18
    .line 19
    iget-object v1, p0, Lh2/ua;->e:Lay0/a;

    .line 20
    .line 21
    iget-object v2, p0, Lh2/ua;->f:Lx2/s;

    .line 22
    .line 23
    iget-wide v3, p0, Lh2/ua;->g:J

    .line 24
    .line 25
    iget-wide v5, p0, Lh2/ua;->h:J

    .line 26
    .line 27
    iget-object v7, p0, Lh2/ua;->i:Lt2/b;

    .line 28
    .line 29
    invoke-static/range {v0 .. v9}, Lh2/wa;->a(ZLay0/a;Lx2/s;JJLt2/b;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
