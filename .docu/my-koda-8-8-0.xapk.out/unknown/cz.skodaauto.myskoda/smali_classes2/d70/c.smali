.class public final synthetic Ld70/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:J

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(FJILjava/lang/String;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ld70/c;->d:F

    .line 5
    .line 6
    iput-wide p2, p0, Ld70/c;->e:J

    .line 7
    .line 8
    iput p4, p0, Ld70/c;->f:I

    .line 9
    .line 10
    iput-object p5, p0, Ld70/c;->g:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/16 p1, 0xc01

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v6

    .line 15
    iget v0, p0, Ld70/c;->d:F

    .line 16
    .line 17
    iget-wide v1, p0, Ld70/c;->e:J

    .line 18
    .line 19
    iget v3, p0, Ld70/c;->f:I

    .line 20
    .line 21
    iget-object v4, p0, Ld70/c;->g:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static/range {v0 .. v6}, Ljp/sf;->e(FJILjava/lang/String;Ll2/o;I)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
