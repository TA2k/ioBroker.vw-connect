.class public final synthetic Lh2/o5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Lc1/n0;

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Le1/n1;

.field public final synthetic h:Le3/n0;

.field public final synthetic i:J

.field public final synthetic j:F

.field public final synthetic k:F

.field public final synthetic l:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/o5;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/o5;->e:Lc1/n0;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/o5;->f:Ll2/b1;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/o5;->g:Le1/n1;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/o5;->h:Le3/n0;

    .line 13
    .line 14
    iput-wide p6, p0, Lh2/o5;->i:J

    .line 15
    .line 16
    iput p8, p0, Lh2/o5;->j:F

    .line 17
    .line 18
    iput p9, p0, Lh2/o5;->k:F

    .line 19
    .line 20
    iput-object p10, p0, Lh2/o5;->l:Lt2/b;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/16 p1, 0x181

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v11

    .line 15
    iget-object v0, p0, Lh2/o5;->d:Lx2/s;

    .line 16
    .line 17
    iget-object v1, p0, Lh2/o5;->e:Lc1/n0;

    .line 18
    .line 19
    iget-object v2, p0, Lh2/o5;->f:Ll2/b1;

    .line 20
    .line 21
    iget-object v3, p0, Lh2/o5;->g:Le1/n1;

    .line 22
    .line 23
    iget-object v4, p0, Lh2/o5;->h:Le3/n0;

    .line 24
    .line 25
    iget-wide v5, p0, Lh2/o5;->i:J

    .line 26
    .line 27
    iget v7, p0, Lh2/o5;->j:F

    .line 28
    .line 29
    iget v8, p0, Lh2/o5;->k:F

    .line 30
    .line 31
    iget-object v9, p0, Lh2/o5;->l:Lt2/b;

    .line 32
    .line 33
    invoke-static/range {v0 .. v11}, Lh2/q5;->a(Lx2/s;Lc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
