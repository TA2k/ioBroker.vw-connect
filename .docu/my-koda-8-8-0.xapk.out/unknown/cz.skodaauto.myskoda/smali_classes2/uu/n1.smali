.class public final synthetic Luu/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/util/ArrayList;

.field public final synthetic e:Z

.field public final synthetic f:J

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:J

.field public final synthetic i:F

.field public final synthetic j:Z

.field public final synthetic k:F

.field public final synthetic l:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;ZJLjava/util/List;JFZFLay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu/n1;->d:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-boolean p2, p0, Luu/n1;->e:Z

    .line 7
    .line 8
    iput-wide p3, p0, Luu/n1;->f:J

    .line 9
    .line 10
    iput-object p5, p0, Luu/n1;->g:Ljava/util/List;

    .line 11
    .line 12
    iput-wide p6, p0, Luu/n1;->h:J

    .line 13
    .line 14
    iput p8, p0, Luu/n1;->i:F

    .line 15
    .line 16
    iput-boolean p9, p0, Luu/n1;->j:Z

    .line 17
    .line 18
    iput p10, p0, Luu/n1;->k:F

    .line 19
    .line 20
    iput-object p11, p0, Luu/n1;->l:Lay0/k;

    .line 21
    .line 22
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
    const/16 p1, 0x31

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v12

    .line 15
    iget-object v0, p0, Luu/n1;->d:Ljava/util/ArrayList;

    .line 16
    .line 17
    iget-boolean v1, p0, Luu/n1;->e:Z

    .line 18
    .line 19
    iget-wide v2, p0, Luu/n1;->f:J

    .line 20
    .line 21
    iget-object v4, p0, Luu/n1;->g:Ljava/util/List;

    .line 22
    .line 23
    iget-wide v5, p0, Luu/n1;->h:J

    .line 24
    .line 25
    iget v7, p0, Luu/n1;->i:F

    .line 26
    .line 27
    iget-boolean v8, p0, Luu/n1;->j:Z

    .line 28
    .line 29
    iget v9, p0, Luu/n1;->k:F

    .line 30
    .line 31
    iget-object v10, p0, Luu/n1;->l:Lay0/k;

    .line 32
    .line 33
    invoke-static/range {v0 .. v12}, Llp/ja;->a(Ljava/util/ArrayList;ZJLjava/util/List;JFZFLay0/k;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
