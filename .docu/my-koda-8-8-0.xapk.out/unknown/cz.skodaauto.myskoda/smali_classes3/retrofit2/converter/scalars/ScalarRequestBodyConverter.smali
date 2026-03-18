.class final Lretrofit2/converter/scalars/ScalarRequestBodyConverter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lretrofit2/Converter;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lretrofit2/Converter<",
        "TT;",
        "Ld01/r0;",
        ">;"
    }
.end annotation


# static fields
.field public static final d:Lretrofit2/converter/scalars/ScalarRequestBodyConverter;

.field public static final e:Ld01/d0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lretrofit2/converter/scalars/ScalarRequestBodyConverter;

    .line 2
    .line 3
    invoke-direct {v0}, Lretrofit2/converter/scalars/ScalarRequestBodyConverter;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lretrofit2/converter/scalars/ScalarRequestBodyConverter;->d:Lretrofit2/converter/scalars/ScalarRequestBodyConverter;

    .line 7
    .line 8
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 9
    .line 10
    const-string v0, "text/plain; charset=UTF-8"

    .line 11
    .line 12
    invoke-static {v0}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lretrofit2/converter/scalars/ScalarRequestBodyConverter;->e:Ld01/d0;

    .line 17
    .line 18
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Lretrofit2/converter/scalars/ScalarRequestBodyConverter;->e:Ld01/d0;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p0, p1}, Ld01/r0;->create(Ld01/d0;Ljava/lang/String;)Ld01/r0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
