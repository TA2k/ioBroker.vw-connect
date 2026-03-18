.class public final Lud0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lud0/a;


# direct methods
.method public constructor <init>(Lud0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lud0/b;->a:Lud0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lvd0/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lud0/b;->a:Lud0/a;

    .line 2
    .line 3
    check-cast p0, Lsd0/a;

    .line 4
    .line 5
    iget-object p0, p0, Lsd0/a;->a:Lyy0/q1;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvd0/a;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lud0/b;->a(Lvd0/a;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
