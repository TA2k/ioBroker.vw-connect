.class public final synthetic Lc41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Ljava/lang/Integer;

.field public final synthetic f:Ljava/util/List;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(JLjava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lc41/a;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lc41/a;->e:Ljava/lang/Integer;

    .line 7
    .line 8
    iput-object p4, p0, Lc41/a;->f:Ljava/util/List;

    .line 9
    .line 10
    iput-object p5, p0, Lc41/a;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p6, p0, Lc41/a;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p7, p0, Lc41/a;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p8, p0, Lc41/a;->j:Lay0/k;

    .line 17
    .line 18
    iput p9, p0, Lc41/a;->k:I

    .line 19
    .line 20
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
    iget p1, p0, Lc41/a;->k:I

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
    iget-wide v0, p0, Lc41/a;->d:J

    .line 18
    .line 19
    iget-object v2, p0, Lc41/a;->e:Ljava/lang/Integer;

    .line 20
    .line 21
    iget-object v3, p0, Lc41/a;->f:Ljava/util/List;

    .line 22
    .line 23
    iget-object v4, p0, Lc41/a;->g:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v5, p0, Lc41/a;->h:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v6, p0, Lc41/a;->i:Lay0/k;

    .line 28
    .line 29
    iget-object v7, p0, Lc41/a;->j:Lay0/k;

    .line 30
    .line 31
    invoke-static/range {v0 .. v9}, Ljp/vc;->a(JLjava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
