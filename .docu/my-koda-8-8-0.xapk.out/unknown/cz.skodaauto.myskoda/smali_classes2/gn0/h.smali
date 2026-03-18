.class public final Lgn0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lrs0/g;


# direct methods
.method public constructor <init>(Lrs0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgn0/h;->a:Lrs0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lgn0/h;->a:Lrs0/g;

    .line 2
    .line 3
    iget-object p0, p0, Lrs0/g;->a:Lrs0/f;

    .line 4
    .line 5
    check-cast p0, Lps0/f;

    .line 6
    .line 7
    iget-object p0, p0, Lps0/f;->c:Lyy0/i;

    .line 8
    .line 9
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v0, La50/h;

    .line 14
    .line 15
    const/16 v1, 0x1a

    .line 16
    .line 17
    invoke-direct {v0, p0, v1}, La50/h;-><init>(Lyy0/i;I)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method
