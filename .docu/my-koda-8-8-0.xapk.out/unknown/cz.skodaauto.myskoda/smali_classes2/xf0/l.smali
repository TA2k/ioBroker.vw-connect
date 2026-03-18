.class public final synthetic Lxf0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Z

.field public final synthetic h:J

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:Z

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZZLay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/l;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/l;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/l;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Lxf0/l;->g:Z

    .line 11
    .line 12
    iput-wide p5, p0, Lxf0/l;->h:J

    .line 13
    .line 14
    iput-boolean p7, p0, Lxf0/l;->i:Z

    .line 15
    .line 16
    iput-boolean p8, p0, Lxf0/l;->j:Z

    .line 17
    .line 18
    iput-boolean p9, p0, Lxf0/l;->k:Z

    .line 19
    .line 20
    iput-object p10, p0, Lxf0/l;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p11, p0, Lxf0/l;->m:Lay0/a;

    .line 23
    .line 24
    iput p12, p0, Lxf0/l;->n:I

    .line 25
    .line 26
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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lxf0/l;->n:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v12

    .line 17
    iget-object v0, p0, Lxf0/l;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Lxf0/l;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v2, p0, Lxf0/l;->f:Ljava/lang/String;

    .line 22
    .line 23
    iget-boolean v3, p0, Lxf0/l;->g:Z

    .line 24
    .line 25
    iget-wide v4, p0, Lxf0/l;->h:J

    .line 26
    .line 27
    iget-boolean v6, p0, Lxf0/l;->i:Z

    .line 28
    .line 29
    iget-boolean v7, p0, Lxf0/l;->j:Z

    .line 30
    .line 31
    iget-boolean v8, p0, Lxf0/l;->k:Z

    .line 32
    .line 33
    iget-object v9, p0, Lxf0/l;->l:Lay0/a;

    .line 34
    .line 35
    iget-object v10, p0, Lxf0/l;->m:Lay0/a;

    .line 36
    .line 37
    invoke-static/range {v0 .. v12}, Lxf0/m;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZZLay0/a;Lay0/a;Ll2/o;I)V

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method
