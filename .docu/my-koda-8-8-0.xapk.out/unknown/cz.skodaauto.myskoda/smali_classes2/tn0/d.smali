.class public final Ltn0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ltn0/f;


# direct methods
.method public constructor <init>(Ltn0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltn0/d;->a:Ltn0/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lun0/a;)Lyy0/i;
    .locals 2

    .line 1
    iget-object p0, p0, Ltn0/d;->a:Ltn0/f;

    .line 2
    .line 3
    check-cast p0, Lrn0/i;

    .line 4
    .line 5
    iget-object p0, p0, Lrn0/i;->e:Lag/r;

    .line 6
    .line 7
    new-instance v0, Llb0/y;

    .line 8
    .line 9
    const/16 v1, 0xd

    .line 10
    .line 11
    invoke-direct {v0, v1, p0, p1}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    new-instance p0, Lrz/k;

    .line 15
    .line 16
    const/16 p1, 0x15

    .line 17
    .line 18
    invoke-direct {p0, v0, p1}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lun0/a;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ltn0/d;->a(Lun0/a;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
